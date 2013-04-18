package main

import (
  "github.com/bickfordb/dynamodb"
  "fmt"
  "os"
  "strings"
)

func envDict() map[string]string {
  result := make(map[string]string)
  for _, envLine := range os.Environ() {
    parts := strings.SplitN(envLine, "=", 2)
    if len(parts) != 2 { continue }
    result[parts[0]] = parts[1]
  }
  return result
}

func main() {
  env := envDict()
  accessKey := env["AWS_ACCESS_KEY"]
  secretKey := env["AWS_SECRET_KEY"]
  endPoint := dynamodb.USEast1
  client := dynamodb.NewClient(accessKey, secretKey, endPoint)
  var err error
  tables, err := client.ListTables()
  if err != nil {
    println("error: ", err.Error())
    return
  }
  fmt.Println("tables:", tables)

  type Item struct {
    ID int `dynamo:"id"`
    Fuzzy string
  }
  item := Item{5, "yes"}
  something := Item{}
  err = client.PutItem("users", item, false)
  if err != nil {
    println("error: ", err.Error())
    return
  }
  err = client.GetItem("users", 5, nil, &something)
  if err != nil {
    println("error: ", err.Error())
    return
  } else {
    fmt.Println("something:", something)
  }
  return
}
