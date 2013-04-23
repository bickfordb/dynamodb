package dynamodb

import (
  "testing"
  "os"
  "strings"
  "math/rand"
  "time"
)

var rangeTable string = "test-range"
var hashTable string = "test-hash"

func environment() map[string]string {
  result := make(map[string]string)
  for _, line := range os.Environ() {
    parts := strings.SplitN(line, "=", 2)
    if len(parts) == 2 { result[parts[0]] = parts[1] }
  }
  return result
}

func getTestClient(t *testing.T) (client *Client) {
  env := environment()
  client = NewClient(env["AWS_ACCESS_KEY"], env["AWS_SECRET_KEY"], env["AWS_REGION"])
  if client == nil {
    t.Fatalf("unable to create client")
  }
  return
}

func check(test *testing.T, err error) {
  if err != nil {
    test.Fatal(err.Error())
  }
}

func makeTestTables(t *testing.T, client *Client) {
  needTables := make(map[string]bool)
  needTables[rangeTable] = true
  needTables[hashTable] = true

  tables, err := client.ListTables()
  check(t, err)
  for _, t := range tables {
    delete(needTables, t)
    continue
  }

  for table, _ := range needTables {
    if table == hashTable {
      _, err = client.CreateTable(table, "AHashKey", "S", "", "")
      check(t, err)
    } else if table == rangeTable {
      _, err = client.CreateTable(table, "AHashKey", "S", "ARangeKey", "S")
      check(t, err)
    }
    for {
      desc, err := client.DescribeTable(table)
      check(t, err)
      if desc.TableStatus == "ACTIVE" { break }
      println("waiting for ", table, " to be created")
      time.Sleep(1 * time.Second)
    }
  }
}

func init() {
  rand.Seed(time.Now().UTC().UnixNano())
}

type rangeItemType struct {
  AHashKey string
  ARangeKey string
  AString string
  AInt int
  AFloat float64
  ABool bool
}

func TestQuery(t *testing.T) {
  client := getTestClient(t)
  makeTestTables(t, client)

  err := client.DeleteItem(rangeTable, map[string]interface{}{"ARangeKey": "x", "AHashKey": "y"})
  check(t, err)
  var item rangeItemType
  item.ARangeKey = "x"
  item.AHashKey = "y"
  item.AString = "Hello"
  err = client.PutItem(rangeTable, item, true)
  rows, err := client.Query(rangeTable, map[string]interface{}{
    "AHashKey": "y",
    "ARangeKey": "x"})
  check(t, err)
  if len(rows) != 1 { t.Fatalf("expecting rows") }
  for _, row := range rows {
    var i rangeItemType
    row.Scan(&i)
    if i != item {
      t.Fatalf("expecting %+v but got %+v", item, i)
    }
  }
  err = client.DeleteItem(rangeTable, map[string]interface{}{"ARangeKey": "x", "AHashKey": "y"})
  check(t, err)
}


