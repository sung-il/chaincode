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
	"encoding/base64"
	"errors"
	"fmt"
	"database/sql"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/op/go-logging"
	_ "github.com/lib/pq"
)

var myLogger = logging.MustGetLogger("asset_mgm")

const (
	DB_USER		= "postgres"
	DB_PASSWORD = ""
	DB_NAME		= "thingsboard"
)

// AssetManagementChaincode is simple chaincode implementing a basic Asset Management system
// with access control enforcement at chaincode level.
// Look here for more information on how to implement access control at chaincode level:
// https://github.com/hyperledger/fabric/blob/master/docs/tech/application-ACL.md
// An asset is simply represented by a string.
type AssetManagementChaincode struct {
}

// Init method will be called during deployment.
// The deploy transaction metadata is supposed to contain the administrator cert
func (t *AssetManagementChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	myLogger.Debug("Init Chaincode...")
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	// Create device table
	err := stub.CreateTable("device", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "id", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "additionalInfo", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "customerId", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "type", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "name", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "searchText", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "tenantId", Type: shim.ColumnDefinition_BYTES, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating device table.")
	}

	// Create deviceCredentials table
	err := stub.CreateTable("deviceCredentials", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "id", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "credentialsId", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "credentialsType", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "credentialsValue", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "deviceId", Type: shim.ColumnDefinition_BYTES, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating deviceCredentials table.")
	}

	// // Set the admin
	// // The metadata will contain the certificate of the administrator
	// adminCert, err := stub.GetCallerMetadata()
	// if err != nil {
	// 	myLogger.Debug("Failed getting metadata")
	// 	return nil, errors.New("Failed getting metadata.")
	// }
	// if len(adminCert) == 0 {
	// 	myLogger.Debug("Invalid admin certificate. Empty.")
	// 	return nil, errors.New("Invalid admin certificate. Empty.")
	// }

	// myLogger.Debug("The administrator is [%x]", adminCert)

	// stub.PutState("admin", adminCert)

	myLogger.Debug("Init Chaincode...done")

	return nil, nil
}

func (t *AssetManagementChaincode) migrate(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debug("Migrate...")

	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	dbinfo := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable",
		DB_USER, DB_PASSWORD, DB_NAME)
		
	db, err := sql.Open("postgres", dbinfo)
	if err != nil {
		return nil, errors.New("Can't open postgresql")
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, additional_info, customer_id, type, name, search_text, tenant_id from device")
	if err != nil {
		return nil, errors.New("Can't get device table")
	}
	defer rows.Close()

	var db_id string
	var db_additional_info string
	var db_customer_id string
	var db_type string
	var db_name string
	var db_search_text string
	var db_tenant_id string
	for rows.Next() {
		err := rows.Scan(&db_id, &db_additional_info, &db_customer_id, &db_type, &db_name, &db_search_text, &db_tenant_id)
		if err != nil {
			return nil, errors.New("Can't get device table rows")
		}

		id := db_id
		additional_info, err := base64.StdEncoding.DecodeString(db_additional_info)
		if err != nil {
			return nil, errors.New("Failed decoding additional_info")
		}
		customer_id, err := base64.StdEncoding.DecodeString(db_customer_id)
		if err != nil {
			return nil, errors.New("Failed decoding db_customer_id")
		}
		type, err := base64.StdEncoding.DecodeString(db_type)
		if err != nil {
			return nil, errors.New("Failed decoding db_type")
		}
		name, err := base64.StdEncoding.DecodeString(db_name)
		if err != nil {
			return nil, errors.New("Failed decoding db_name")
		}
		search_text, err := base64.StdEncoding.DecodeString(db_search_text)
		if err != nil {
			return nil, errors.New("Failed decoding db_search_text")
		}
		tenant_id, err := base64.StdEncoding.DecodeString(db_tenant_id)
		if err != nil {
			return nil, errors.New("Failed decoding db_tenant_id")
		}

		ok, err = stub.InsertRow("device", shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: id}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: additional_info}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: customer_id}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: type}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: name}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: search_text}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: tenant_id}}
			},
		})

		if !ok && err == nil {
			return nil, errors.New("device table was already made.")
		}
	}
	
	// Migrate Complete
	myLogger.Debugf("device Migrate ... Done")
	
	rows, err := db.Query("SELECT id, credentials_id, credentials_type, credentials_value, device_id from device_credentials")
	if err != nil {
		return nil, errors.New("Can't get device_credentials table")
	}
	defer rows.Close()

	var db_id string
	var db_credentials_id string
	var db_credentials_type string
	var db_credentials_value string
	var db_device_id string
	for rows.Next() {
		err := rows.Scan(&db_id, &db_credentials_id, &db_credentials_type, &db_credentials_value, &db_device_id)
		if err != nil {
			return nil, errors.New("Can't get device_credentials table rows")
		}

		id := db_id
		credentials_id, err := base64.StdEncoding.DecodeString(db_credentials_id)
		if err != nil {
			return nil, errors.New("Failed decoding db_credentials_id")
		}
		credentials_type, err := base64.StdEncoding.DecodeString(db_credentials_type)
		if err != nil {
			return nil, errors.New("Failed decoding db_credentials_type")
		}
		credentials_value, err := base64.StdEncoding.DecodeString(db_credentials_value)
		if err != nil {
			return nil, errors.New("Failed decoding db_credentials_value")
		}
		device_id, err := base64.StdEncoding.DecodeString(db_device_id)
		if err != nil {
			return nil, errors.New("Failed decoding db_device_id")
		}

		ok, err = stub.InsertRow("deviceCredentials", shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: id}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: credentials_id}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: credentials_type}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: credentials_value}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: device_id}}
			},
		})

		if !ok && err == nil {
			return nil, errors.New("device_credentials table was already made.")
		}
	}
	
	// Migrate Complete
	myLogger.Debugf("device_credentials Migrate ... Done")

	myLogger.Debug("Migrate...done!")

	return nil, err
}

func (t *AssetManagementChaincode) authenticate(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	return nil, nil
}

// func (t *AssetManagementChaincode) transfer(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
// 	myLogger.Debug("Transfer...")

// 	if len(args) != 2 {
// 		return nil, errors.New("Incorrect number of arguments. Expecting 2")
// 	}

// 	asset := args[0]
// 	newOwner, err := base64.StdEncoding.DecodeString(args[1])
// 	if err != nil {
// 		return nil, fmt.Errorf("Failed decoding owner")
// 	}

// 	// Verify the identity of the caller
// 	// Only the owner can transfer one of his assets
// 	var columns []shim.Column
// 	col1 := shim.Column{Value: &shim.Column_String_{String_: asset}}
// 	columns = append(columns, col1)

// 	row, err := stub.GetRow("AssetsOwnership", columns)
// 	if err != nil {
// 		return nil, fmt.Errorf("Failed retrieving asset [%s]: [%s]", asset, err)
// 	}

// 	prvOwner := row.Columns[1].GetBytes()
// 	myLogger.Debugf("Previous owener of [%s] is [% x]", asset, prvOwner)
// 	if len(prvOwner) == 0 {
// 		return nil, fmt.Errorf("Invalid previous owner. Nil")
// 	}

// 	// Verify ownership
// 	ok, err := t.isCaller(stub, prvOwner)
// 	if err != nil {
// 		return nil, errors.New("Failed checking asset owner identity")
// 	}
// 	if !ok {
// 		return nil, errors.New("The caller is not the owner of the asset")
// 	}

// 	// At this point, the proof of ownership is valid, then register transfer
// 	err = stub.DeleteRow(
// 		"AssetsOwnership",
// 		[]shim.Column{shim.Column{Value: &shim.Column_String_{String_: asset}}},
// 	)
// 	if err != nil {
// 		return nil, errors.New("Failed deliting row.")
// 	}

// 	_, err = stub.InsertRow(
// 		"AssetsOwnership",
// 		shim.Row{
// 			Columns: []*shim.Column{
// 				&shim.Column{Value: &shim.Column_String_{String_: asset}},
// 				&shim.Column{Value: &shim.Column_Bytes{Bytes: newOwner}},
// 			},
// 		})
// 	if err != nil {
// 		return nil, errors.New("Failed inserting row.")
// 	}

// 	myLogger.Debug("New owner of [%s] is [% x]", asset, newOwner)

// 	myLogger.Debug("Transfer...done")

// 	return nil, nil
// }

// func (t *AssetManagementChaincode) isCaller(stub shim.ChaincodeStubInterface, certificate []byte) (bool, error) {
// 	myLogger.Debug("Check caller...")

// 	// In order to enforce access control, we require that the
// 	// metadata contains the signature under the signing key corresponding
// 	// to the verification key inside certificate of
// 	// the payload of the transaction (namely, function name and args) and
// 	// the transaction binding (to avoid copying attacks)

// 	// Verify \sigma=Sign(certificate.sk, tx.Payload||tx.Binding) against certificate.vk
// 	// \sigma is in the metadata

// 	sigma, err := stub.GetCallerMetadata()
// 	if err != nil {
// 		return false, errors.New("Failed getting metadata")
// 	}
// 	payload, err := stub.GetPayload()
// 	if err != nil {
// 		return false, errors.New("Failed getting payload")
// 	}
// 	binding, err := stub.GetBinding()
// 	if err != nil {
// 		return false, errors.New("Failed getting binding")
// 	}

// 	myLogger.Debugf("passed certificate [% x]", certificate)
// 	myLogger.Debugf("passed sigma [% x]", sigma)
// 	myLogger.Debugf("passed payload [% x]", payload)
// 	myLogger.Debugf("passed binding [% x]", binding)

// 	ok, err := stub.VerifySignature(
// 		certificate,
// 		sigma,
// 		append(payload, binding...),
// 	)
// 	if err != nil {
// 		myLogger.Errorf("Failed checking signature [%s]", err)
// 		return ok, err
// 	}
// 	if !ok {
// 		myLogger.Error("Invalid signature")
// 	}

// 	myLogger.Debug("Check caller...Verified!")

// 	return ok, err
// }

// Invoke will be called for every transaction.
// Supported functions are the following:
// "assign(asset, owner)": to assign ownership of assets. An asset can be owned by a single entity.
// Only an administrator can call this function.
// "transfer(asset, newOwner)": to transfer the ownership of an asset. Only the owner of the specific
// asset can call this function.
// An asset is any string to identify it. An owner is representated by one of his ECert/TCert.
func (t *AssetManagementChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	// Handle different functions
	if function == "migrate" {
		// Assign ownership
		return t.migrate(stub, args)
	} else if function == "authenticate" {
		// Transfer ownership
		return t.authenticate(stub, args)
	}
	

	return nil, errors.New("Received unknown function invocation")
}

// Query callback representing the query of a chaincode
// Supported functions are the following:
// "query(asset)": returns the owner of the asset.
// Anyone can invoke this function.
func (t *AssetManagementChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	myLogger.Debugf("Query [%s]", function)

	// if function != "query" {
	// 	return nil, errors.New("Invalid query function name. Expecting 'query' but found '" + function + "'")
	// }

	// var err error

	// if len(args) != 1 {
	// 	myLogger.Debug("Incorrect number of arguments. Expecting name of an asset to query")
	// 	return nil, errors.New("Incorrect number of arguments. Expecting name of an asset to query")
	// }

	// // Who is the owner of the asset?
	// asset := args[0]

	// myLogger.Debugf("Arg [%s]", string(asset))

	// var columns []shim.Column
	// col1 := shim.Column{Value: &shim.Column_String_{String_: asset}}
	// columns = append(columns, col1)

	// row, err := stub.GetRow("AssetsOwnership", columns)
	// if err != nil {
	// 	myLogger.Debugf("Failed retriving asset [%s]: [%s]", string(asset), err)
	// 	return nil, fmt.Errorf("Failed retriving asset [%s]: [%s]", string(asset), err)
	// }

	// myLogger.Debugf("Query done [% x]", row.Columns[1].GetBytes())

	// return row.Columns[1].GetBytes(), nil
	return nil, nil
}

func main() {
	primitives.SetSecurityLevel("SHA3", 256)
	err := shim.Start(new(AssetManagementChaincode))
	if err != nil {
		fmt.Printf("Error starting AssetManagementChaincode: %s", err)
	}
}
