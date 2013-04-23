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
   "github.com/bickfordb/lg"
   "time")

const (
  USEast1 string = "dynamodb.us-east-1.amazonaws.com"
  EndPointFormat = "dynamodb.%s.amazonaws.com"
  hmacAlgorithm = "AWS4-HMAC-SHA256"
  signatureVersion = "aws4_request"
  amzDateFormat = "20060102T150405Z"
  ymdFormat = "20060102"
  service = "dynamodb" // dynamodb?
  Equals = "EQ"
)

var log = lg.GetLog("dynamodb")

func (c *Client) EndPoint() string {
  return fmt.Sprintf(EndPointFormat, c.Region)
}

type Client struct {
  SecretKey string
  AccessKey string
  Region string
}

func NewClient(access string, secret string, region string) *Client {
  if access == "" || secret == "" || region == "" {
    return nil
  }
  return &Client{SecretKey:secret, AccessKey:access, Region:region}
}

func (c *Client) Authorization(request *http.Request, body []byte, at time.Time) (result string) {
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
  credentialScope := requestYMD + "/" + c.Region + "/" + service + "/" + signatureVersion
  credential := c.AccessKey + "/" + credentialScope
  signingString := hmacAlgorithm + "\n" + at.Format(amzDateFormat) + "\n" + credentialScope + "\n" + canonicalSignature
  kDate := hmacsha256([]byte("AWS4" + c.SecretKey), []byte(requestYMD))
  kRegion := hmacsha256(kDate, []byte(c.Region))
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

func (c *Client) DeleteItem(table string, keys map[string]interface{}) (err error) {
  var in struct {
    Key map[string]AttributeValue
    TableName string
  }
  in.TableName = table
  in.Key = make(map[string]AttributeValue)
  for key, val := range keys {
    in.Key[key] = toDynamoAttrVal(val)
  }
  var out struct {
  }
  err = c.runJSONRequest("DeleteItem", in, &out)
  return
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
    xs, ok := attrVal["S"]
    if attrVal != nil && (!ok || xs != "") {
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
  println("run json", method, string(body))
  bodyBuf := bytes.NewBuffer(body)
  hc := &http.Client{}
  now := time.Now().UTC()
  endPoint := c.EndPoint()
  req, err := http.NewRequest("POST", "http://" + endPoint + "/", bodyBuf)
  req.Header.Set("Host", endPoint)
  req.Header.Set("x-amz-date", now.Format(amzDateFormat))
  req.Header.Set("x-amz-target", "DynamoDB_20120810." + method)
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
  case bool:
    s := "0"
    if unk { s = "1" }
    result = map[string]string{"N": s}
  }
  return
}
//

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
    dynoField := DynamoName(t.Field(i))
    valField := outV.Field(i)
    setField(&valField, result.Item[dynoField])
  }
  return
}

func (c *Client) ListTables() (tables []string, err error) {
  var params struct{
    Limit int}
  params.Limit = 100
  var out struct {
    TableNames []string
  }
  err = c.runJSONRequest("ListTables", params, &out)
  if err != nil { return }
  tables = out.TableNames
  return
}

type AmazonFailure struct {
  Code int
  Message string
}

func (a *AmazonFailure) Error() string {
  return fmt.Sprintf("amazon failure (%d) --- %q", a.Code, a.Message)
}

type TableDescription struct {
  CreationDateTime float64
  ItemCount int
  KeySchema []KeySchema
  AttributeDefinitions []AttributeDefinition
  TableName string
  TableSizeBytes int
  TableStatus string
}

type AttributeDefinition struct {
  AttributeName string
  AttributeType string
}
type KeySchema struct {
  AttributeName string
  KeyType string
}

func (c *Client) CreateTable(name string, hashName string, hashType string, rangeName string, rangeType string) (description *TableDescription, err error) {
  if hashName == "" {
    err = fmt.Errorf("expecting hashName")
    return
  }
  if hashType == "" {
    err = fmt.Errorf("expecting hashType")
    return
  }
  if rangeName != "" && rangeType == "" {
    err = fmt.Errorf("expecting rangeType")
    return
  }
  type LocalSecondaryIndex struct {
    IndexName string
    KeySchema []KeySchema
    Projection struct {
      ProjectionType string
    }
  }

  var in struct {
    TableName string
    ProvisionedThroughput struct {
      ReadCapacityUnits int
      WriteCapacityUnits int
    }
    AttributeDefinitions []AttributeDefinition
    LocalSecondaryIndexes []LocalSecondaryIndex `json:"LocalSecondaryIndexes,omitempty"`
    KeySchema []KeySchema
  }
  in.LocalSecondaryIndexes = make([]LocalSecondaryIndex, 0)
  in.TableName = name
  in.ProvisionedThroughput.ReadCapacityUnits = 1
  in.ProvisionedThroughput.WriteCapacityUnits = 1
  in.KeySchema = append(in.KeySchema, KeySchema{hashName, "HASH"})
  in.AttributeDefinitions = append(in.AttributeDefinitions, AttributeDefinition{hashName, hashType})
  if rangeName != "" {
    in.KeySchema = append(in.KeySchema, KeySchema{rangeName, "RANGE"})
    in.AttributeDefinitions = append(in.AttributeDefinitions, AttributeDefinition{rangeName, rangeType})
  }
  var out struct {
    TableDescription TableDescription
  }
  err = c.runJSONRequest("CreateTable", in, &out)
  if err != nil { return }
  description = &out.TableDescription
  return
}

func (c *Client) DeleteTable(name string) (err error) {
  var in struct {
    TableName string
  }
  var out struct {
  }
  in.TableName = name
  err = c.runJSONRequest("DeleteTable", &in, &out)
  return
}


func (c *Client) DescribeTable(name string) (desc TableDescription, err error) {
  var in struct {
    TableName string
  }
  in.TableName = name
  var out struct {
    Table TableDescription
  }
  err = c.runJSONRequest("DescribeTable", in, &out)
  if err != nil { return }
  desc = out.Table
  return
}

type AttributeValue map[string]string

type KeyCondition struct {
  AttributeValueList []AttributeValue `json:"",omitempty`
  ComparisonOperator string
}

type QueryRequest struct {
  AttributesToGet []string `json:"",omitempty`
  ConsistentRead bool
  ExclusiveStartKey map[string]string `json:"",omitempty`
  IndexName string `json:"IndexName,omitempty"`
  KeyConditions map[string]KeyCondition `json:"",omitempty`
  //Limit int
  //ReturnConsumedCapacity string `json:"",omitempty`
  ScanIndexForward bool
  Select string
  TableName string
}

type Row map[string]AttributeValue

func (r Row) Scan(item interface {}) {
  vP := reflect.ValueOf(item)
  tP := reflect.TypeOf(item)
  if tP.Kind() != reflect.Ptr { return }
  vS := vP.Elem()
  tS := vS.Type()
  numFields := vS.NumField()
  for i := 0; i < numFields; i += 1 {
    typeField := tS.Field(i)
    valField := vS.Field(i)
    key := DynamoName(typeField)
    val := r[key]
    setField(&valField, val)
  }
}

func setField(field *reflect.Value, dynAttr map[string]string) {
  switch kind := field.Kind(); kind {
  case reflect.String:
    val := ""
    if dynAttr != nil {
      val = dynAttr["S"]
    }
    field.SetString(val)
  case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
    var val int64 = 0
    if dynAttr != nil {
      f, e := strconv.ParseFloat(dynAttr["N"], 64)
      if e != nil { val = int64(f) }
    }
    field.SetInt(val)
  case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
    var val uint64
    if dynAttr != nil {
      f, e := strconv.ParseFloat(dynAttr["N"], 64)
      if e != nil { val = uint64(f) }
    }
    field.SetUint(val)
  case reflect.Float32, reflect.Float64:
    var val float64
    if dynAttr != nil {
      f, e := strconv.ParseFloat(dynAttr["N"], 64)
      if e != nil { val = f }
    }
    field.SetFloat(val)
  case reflect.Bool:
    var val bool
    if dynAttr != nil {
      f, e := strconv.ParseFloat(dynAttr["N"], 64)
      if e != nil { val = f != 0 }
    }
    field.SetBool(val)
  default:
    panic("unexpected type")
    return
  }
}


func (c *Client) Query(table string, keys map[string]interface{}) (rows []Row, err error) {
  if len(keys) == 0 {
    err = fmt.Errorf("expecting keys")
    return
  }
  var in QueryRequest
  in.TableName = table
  in.Select = "ALL_ATTRIBUTES"
  in.KeyConditions = make(map[string]KeyCondition)
  //in.Limit = 100
  for key, val := range keys {
    in.KeyConditions[key] = KeyCondition{
      AttributeValueList: []AttributeValue{toDynamoAttrVal(val)},
      ComparisonOperator: Equals}
  }

  var out struct {
    Count int
    Items []map[string]AttributeValue
    LastEvaluatedKey map[string]AttributeValue
  }
  err = c.runJSONRequest("Query", in, &out)
  if err != nil { return }
  count := 0
  if out.Count >= 0 { count = out.Count }
  rows = make([]Row, 0, count)
  for _, i := range out.Items {
    rows = append(rows, i)
  }
  return
}
