package dynamodb

import (
   "bytes"
   "crypto/hmac"
   "crypto/sha256"
   "encoding/json"
   "fmt"
   "io"
   "net/http"
   "reflect"
   "sort"
   "strings"
   "strconv"
   "time")

const (
  USEast1 string = "dynamodb.us-east-1.amazonaws.com"
  hmacAlgorithm = "AWS4-HMAC-SHA256"
  signatureVersion = "aws4_request"
  amzDateFormat = "20060102T150405Z"
  ymdFormat = "20060102"
  regionName = "us-east-1"
  service = "dynamodb" // dynamodb?
)

type Client struct {
  SecretKey string
  AccessKey string
  EndPoint string
}

func NewClient(access string, secret string, endPoint string) *Client {
  return &Client{SecretKey:secret, AccessKey:access, EndPoint:endPoint}
}

func (c *Client) Authorization(request *http.Request, body []byte, at time.Time) (result string) {
  //authorization := "AWS4-HMAC-SHA256 Credential=AccessKeyID/20120116/us-east-1/dynamodb/aws4_request,SignedHeaders=host;x-amz-date;x-amz-target,Signature=145b1567ab3c50d929412f28f52c45dbf1e63ec5c66023d232a539a4afd11fd9"
  canonical := bytes.Buffer{}
  canonical.WriteString(strings.ToUpper(request.Method))
  canonical.WriteString("\n")
  path := request.URL.Path
  if path == "" { path = "/" }
  canonical.WriteString(path)
  canonical.WriteString("\n")
  canonical.WriteString(request.URL.RawQuery)
  canonical.WriteString("\n") // empty query string
  headerKeys := make([]string, 0, len(request.Header))
  headers0 := make(map[string][]string)
  for key, vals := range request.Header {
    key = strings.ToLower(key)
    headerKeys = append(headerKeys, key)
    headers0[key] = vals
  }
  sort.Strings(headerKeys)
  signedHeaders := ""
  for idx, key := range headerKeys {
    for _, val := range headers0[key] {
      canonical.WriteString(key)
      canonical.WriteString(":")
      canonical.WriteString(strings.TrimSpace(val))
      canonical.WriteString("\n")
    }
    if idx != 0 { signedHeaders += ";" }
    signedHeaders += key
  }
  canonical.WriteString("\n")
  canonical.WriteString(signedHeaders)
  canonical.WriteString("\n")
  canonical.WriteString(tosha256hex(body))
  canonicalSignature := tosha256hex(canonical.Bytes())
  requestYMD := at.Format(ymdFormat)
  credentialScope := requestYMD + "/" + regionName + "/" + service + "/" + signatureVersion
  credential := c.AccessKey + "/" + credentialScope
  signingString := hmacAlgorithm + "\n" + at.Format(amzDateFormat) + "\n" + credentialScope + "\n" + canonicalSignature
  kDate := hmacsha256([]byte("AWS4" + c.SecretKey), []byte(requestYMD))
  kRegion := hmacsha256(kDate, []byte(regionName))
  kService := hmacsha256(kRegion, []byte(service))
  kSigning := hmacsha256(kService, []byte("aws4_request"))
  sig := toHex(hmacsha256(kSigning, []byte(signingString)))
  auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=" + credential + ",SignedHeaders=" + signedHeaders + ",Signature=" + sig)
  return auth
}

func toHex(x []byte) string {
  return fmt.Sprintf("%x", x)
}

func hmacsha256(key []byte, message []byte) []byte {
  h := hmac.New(sha256.New, key)
  h.Write(message)
  return h.Sum(nil)
}

func tosha256hex(src []byte) (dst string) {
  h := sha256.New()
  h.Write(src)
  bs := h.Sum(nil)
  return toHex(bs)
}

func DynamoName(field reflect.StructField) (name string) {
  tag := field.Tag
  d := tag.Get("dynamo")
  if d != "" {
    return d
  } else {
    return field.Name
  }
}

func (c *Client) PutItem(table string, item interface{}, replace bool) (err error) {
  var in struct {
    TableName string
    Item map[string]map[string]string
  }
  in.TableName = table
  in.Item = make(map[string]map[string]string)
  if item == nil { return fmt.Errorf("expecting non-nil") }
  theType := reflect.TypeOf(item)
  theValue := reflect.ValueOf(item)
  if theType.Kind() != reflect.Struct { return fmt.Errorf("expecting struct for item") }
  numFields := theType.NumField()
  for i := 0; i < numFields; i++ {
    sf := theType.Field(i)
    vf := theValue.Field(i)
    v := vf.Interface()
    attrName := DynamoName(sf)
    attrVal := toDynamoAttrVal(v)
    if attrVal != nil {
      in.Item[attrName] = attrVal
    }
  }
  var out struct {
    Attributes map[string]string
  }
  out = out
  fmt.Println("in", in)
  err = c.runJSONRequest("PutItem", &in, nil)
  return
}

func (c *Client) runJSONRequest(method string, in interface{}, out interface{}) (err error) {
  body, _ := json.Marshal(in)
  bodyBuf := bytes.NewBuffer(body)
  hc := &http.Client{}
  now := time.Now().UTC()
  req, err := http.NewRequest("POST", "http://" + c.EndPoint + "/", bodyBuf)
  req.Header.Set("Host", c.EndPoint)
  req.Header.Set("x-amz-date", now.Format(amzDateFormat))
  req.Header.Set("x-amz-target", "DynamoDB_20111205." + method)
  req.Header.Set("Content-Type", "application/x-amz-json-1.0")
  req.Header.Set("Date", now.Format(time.RFC1123))
  req.Header.Set("Authorization", c.Authorization(req, body, now))

  response, err := hc.Do(req)
  if err == io.EOF { err = nil }
  if err != nil { return }
  defer response.Body.Close()
  if response.StatusCode != 200 {
    errBuf := &bytes.Buffer{}
    io.Copy(errBuf, response.Body)
    err = &AmazonFailure{response.StatusCode, errBuf.String()}
    return
  }
  if out == nil { return }

  err = json.NewDecoder(response.Body).Decode(out)
  if err == io.EOF { err = nil }
  return
}

func toDynamoAttrVal(value interface{}) (result map[string]string) {
  switch unk := value.(type) {
  case string:
    result = map[string]string{"S": unk}
  case int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64:
    result = map[string]string{"N": fmt.Sprintf("%d", unk)}
  }
  return
}

func (c *Client) GetItem(table string, hashKey interface {}, rangeKey interface {}, out interface{}) (err error) {
  if (out == nil) { return fmt.Errorf("expecting out") }
  tOut := reflect.TypeOf(out)
  if (tOut.Kind() != reflect.Ptr) { return fmt.Errorf("expecting ptr to struct") }
  outV := reflect.ValueOf(out).Elem()


  var in struct {
    TableName string
    Key struct {
      HashKeyElement map[string]string `json:'',omitempty`
      RangeKeyElement map[string]string `json:'',omitempty`
    }
    AttributesToGet []string
  }
  in.TableName = table
  in.Key.HashKeyElement = toDynamoAttrVal(hashKey)
  in.Key.RangeKeyElement = toDynamoAttrVal(rangeKey)
  t := reflect.TypeOf(outV.Interface())
  for i := 0; i < t.NumField(); i += 1 {
    in.AttributesToGet = append(in.AttributesToGet, DynamoName(t.Field(i)))
  }
  var result struct {
    Item map[string]map[string]string
    ConsumedCapacityUnits float32
  }
  err = c.runJSONRequest("GetItem", in, &result)
  fmt.Println("result", result)
  for i := 0; i < t.NumField(); i += 1 {
    structField := t.Field(i)
    dynoField := DynamoName(structField)
    if result.Item[dynoField] == nil { continue }
    valField := outV.Field(i)
    for key, s := range result.Item[dynoField] {
      switch k := valField.Kind(); k {
      case reflect.String:
        if key == "S" {
          valField.SetString(s)
        }
      case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
        if key == "N" {
          f, e := strconv.ParseFloat(s, 64)
          if e != nil { err = e; return }
          f0 := int64(f)
          valField.SetInt(f0)
        }
      case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
        if key == "N" {
          f, e := strconv.ParseFloat(s, 64)
          if e != nil { err = e; return }
          f0 := uint64(f)
          valField.SetUint(f0)
        }
      case reflect.Float32, reflect.Float64:
        if key == "N" {
          f, e := strconv.ParseFloat(s, 64)
          if e != nil { err = e; return }
          valField.SetFloat(f)
        }
      default:
        err = fmt.Errorf("unexpected kind %s", k)
        return
      }
    }
  }
  return
}

func (c *Client) ListTables() (tables []string, err error) {
  var params struct{
    Limit int}
  params.Limit = 100
  body, _ := json.Marshal(params)
  bodyBuf := bytes.NewBuffer(body)
  hc := &http.Client{}
  now := time.Now().UTC()
  req, err := http.NewRequest("POST", "http://" + c.EndPoint + "/", bodyBuf)
  req.Header.Set("Host", c.EndPoint)
  req.Header.Set("x-amz-date", now.Format(amzDateFormat))
  req.Header.Set("x-amz-target", "DynamoDB_20111205.ListTables")
  req.Header.Set("Content-Type", "application/x-amz-json-1.0")
  req.Header.Set("Date", now.Format(time.RFC1123))
  req.Header.Set("Authorization", c.Authorization(req, body, now))

  response, err := hc.Do(req)
  if err == io.EOF { err = nil }
  if err != nil { return }
  defer response.Body.Close()
  if response.StatusCode != 200 {
    errBuf := &bytes.Buffer{}
    io.Copy(errBuf, response.Body)
    err = &AmazonFailure{response.StatusCode, errBuf.String()}
    return
  }
  var msg struct {
    TableNames []string
  }
  err = json.NewDecoder(response.Body).Decode(&msg)
  if err == io.EOF { err = nil }
  if err != nil { return }
  tables = msg.TableNames
  return
}

type AmazonFailure struct {
  Code int
  Message string
}

func (a *AmazonFailure) Error() string {
  return fmt.Sprintf("amazon failure (%d) --- %q", a.Code, a.Message)
}


