/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/lib/pq"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

// This chaincode implements a simple map that is stored in the state.
// The following operations are available.

// Invoke operations
// put - requires two arguments, a key and value
// remove - requires a key

// Query operations
// get - requires one argument, a key, and returns a value
// keys - requires no arguments, returns all keys

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
}

// Init is a no-op
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	// Create deviceCredentials table
	err := stub.CreateTable("deviceCredentials", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "id", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "credentialsId", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "deviceId", Type: shim.ColumnDefinition_BYTES, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating deviceCredentials table")
	}

	return nil, nil
}

// Invoke has two functions
// put - takes two arguements, a key and value, and stores them in the state
// remove - takes one argument, a key, and removes if from the state
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	switch function {
	case "migrate":
		if len(args) != 0 {
			return nil, errors.New("Incorrect number of arguments. Expecting 0")
		}

		dbinfo := fmt.Sprintf("postgres://postgres@203.253.25.140:32902/thingsboard?sslmode=disable")

		db, err := sql.Open("postgres", dbinfo)
		if err != nil {
			return nil, errors.New("Can't open postgresql")
		}
		defer db.Close()

		rows, err := db.Query("SELECT id, credentials_id, device_id from device_credentials")
		if err != nil {
			return nil, errors.New("Can't get device_credentials table")
		}
		defer rows.Close()

		var dbID string
		var dbCredentialsID string
		var dbDeviceID string
		var ccID string
		var ccCredentialsID []byte
		var ccDeviceID []byte
		for rows.Next() {
			err := rows.Scan(&dbID, &dbCredentialsID, &dbDeviceID)
			if err != nil {
				return nil, errors.New("Can't get device_credentials table rows")
			}

			ccID = string(dbID)
			ccCredentialsID = []byte(dbCredentialsID)
			ccDeviceID = []byte(dbDeviceID)

			var columns []*shim.Column

			cmID := shim.Column{Value: &shim.Column_String_{String_: ccID}}
			cmCredentialsID := shim.Column{Value: &shim.Column_String_{Bytes: ccCredentialsID}}
			cmDeviceID := shim.Column{Value: &shim.Column_String_{Bytes: ccDeviceID}}

			columns = append(columns, &cmID)
			columns = append(columns, &cmCredentialsID)
			columns = append(columns, &cmDeviceID)

			row := shim.Row{Columns: columns}
			ok, err := stub.InsertRow("deviceCredentials", row)
			if err != nil {
				return nil, fmt.Errorf("Create operation failed. %s", err)
			}

			// ok, err := stub.InsertRow("deviceCredentials", shim.Row{
			// 	Columns: []*shim.Column{
			// 		&shim.Column{Value: &shim.Column_String_{String_: ccID}},
			// 		&shim.Column{Value: &shim.Column_Bytes{Bytes: ccCredentialsID}},
			// 		&shim.Column{Value: &shim.Column_Bytes{Bytes: ccDeviceID}}},
			// })

			if !ok && err == nil {
				return nil, errors.New("device_credentials table was already made")
			}
		}

		return nil, err

	default:
		return nil, errors.New("Unsupported operation")
	}
}

// Query has two functions
// get - takes one argument, a key, and returns the value for the key
// keys - returns all keys stored in this chaincode
func (t *SimpleChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	switch function {

	case "query":
		if len(args) < 1 {
			return nil, errors.New("get operation must include one argument, a id")
		}

		ccTestID := args[0]

		var columns []shim.Column
		col1 := shim.Column{Value: &shim.Column_String_{String_: ccTestID}}
		columns = append(columns, col1)

		row, err := stub.GetRow("device", columns)
		if err != nil {
			return nil, fmt.Errorf("Failed  get data [%s]: [%s]", "device", err)
		}

		return row.Columns[1].GetBytes(), nil

	default:
		return nil, errors.New("Unsupported operation")
	}
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting chaincode: %s", err)
	}
}
