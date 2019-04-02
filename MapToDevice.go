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
	"encoding/json"
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

		dbinfo := fmt.Sprintf("postgres://postgres@203.253.25.105:5432/thingsboard?sslmode=disable")

		db, err := sql.Open("postgres", dbinfo)
		if err != nil {
			return nil, errors.New("Can't open postgresql")
		}
		defer db.Close()

		rows, err := db.Query("SELECT id, credentials_id from device_credentials")
		if err != nil {
			return nil, errors.New("Can't get device_credentials table")
		}
		defer rows.Close()

		var dbID string
		var dbCredentialsID string
		var ccID []byte
		var ccCredentialsID string
		for rows.Next() {
			err := rows.Scan(&dbID, &dbCredentialsID)
			if err != nil {
				return nil, errors.New("Can't get device_credentials table rows")
			}

			ccCredentialsID = string(dbCredentialsID)
			ccID = []byte(dbID)

			err = stub.PutState(ccCredentialsID, ccID)
			if err != nil {
				fmt.Printf("Error putting state %s", err)
				return nil, fmt.Errorf("put operation failed. Error updating state: %s", err)
			}
		}

		return nil, nil

	case "remove":
		if len(args) != 0 {
			return nil, errors.New("Incorrect number of arguments. Expecting 0")
		}

		keysIter, err := stub.RangeQueryState("", "")
		if err != nil {
			return nil, fmt.Errorf("keys operation failed. Error accessing state: %s", err)
		}
		defer keysIter.Close()

		for keysIter.HasNext() {
			key, _, iterErr := keysIter.Next()
			if iterErr != nil {
				return nil, fmt.Errorf("keys operation failed. Error accessing state: %s", err)
			}
			err := stub.DelState(key)
			if err != nil {
				return nil, fmt.Errorf("remove operation failed. Error updating state: %s", err)
			}
		}

		return nil, nil

	default:
		return nil, errors.New("Unsupported operation")
	}
}

// Query has two functions
// get - takes one argument, a key, and returns the value for the key
// keys - returns all keys stored in this chaincode
func (t *SimpleChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	switch function {

	case "get":
		if len(args) < 1 {
			return nil, errors.New("get operation must include one argument, a key")
		}
		key := args[0]
		value, err := stub.GetState(key)
		if err != nil {
			return nil, fmt.Errorf("get operation failed. Error accessing state: %s", err)
		}
		return value, nil

	case "keys":

		keysIter, err := stub.RangeQueryState("", "")
		if err != nil {
			return nil, fmt.Errorf("keys operation failed. Error accessing state: %s", err)
		}
		defer keysIter.Close()

		var keys []string
		for keysIter.HasNext() {
			key, _, iterErr := keysIter.Next()
			if iterErr != nil {
				return nil, fmt.Errorf("keys operation failed. Error accessing state: %s", err)
			}
			keys = append(keys, key)
		}

		jsonKeys, err := json.Marshal(keys)
		if err != nil {
			return nil, fmt.Errorf("keys operation failed. Error marshaling JSON: %s", err)
		}

		return jsonKeys, nil

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
