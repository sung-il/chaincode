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
	_ "encoding/base64"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	_ "github.com/lib/pq"
	logging "github.com/op/go-logging"
)

var myLogger = logging.MustGetLogger("device_mgmt")

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
		return nil, errors.New("Failed creating device table")
	}

	// Create deviceCredentials table
	err = stub.CreateTable("deviceCredentials", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "id", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "credentialsId", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "credentialsType", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "credentialsValue", Type: shim.ColumnDefinition_BYTES, Key: false},
		&shim.ColumnDefinition{Name: "deviceId", Type: shim.ColumnDefinition_BYTES, Key: false},
	})
	if err != nil {
		return nil, errors.New("Failed creating deviceCredentials table")
	}

	myLogger.Debug("Init Chaincode...done")

	return nil, nil
}

func (t *AssetManagementChaincode) migrate(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debug("Migrate...")

	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	dbinfo := fmt.Sprintf("postgres://postgres@203.253.25.140:32810/thingsboard?sslmode=disable")

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

	var dbID string
	var dbAdditionalInfo string
	var dbCustomerID string
	var dbType string
	var dbName string
	var dbSearchText string
	var dbTenantID string
	var ccID []byte
	var ccAdditionalInfo []byte
	var ccCustomerID []byte
	var ccTypes []byte
	var ccName []byte
	var ccSearchText []byte
	var ccTenantID []byte
	for rows.Next() {
		err := rows.Scan(&dbID, &dbAdditionalInfo, &dbCustomerID, &dbType, &dbName, &dbSearchText, &dbTenantID)
		if err != nil {
			return nil, errors.New("Can't get device table rows")
		}

		ccID = dbID
		ccAdditionalInfo = []byte(dbAdditionalInfo)
		ccCustomerID = []byte(dbCustomerID)
		ccTypes = []byte(dbType)
		ccName = []byte(dbName)
		ccSearchText = []byte(dbSearchText)
		ccTenantID = []byte(dbTenantID)

		// ccAdditionalInfo, err := base64.StdEncoding.DecodeString(dbAdditionalInfo)
		// if err != nil {
		// 	return nil, errors.New("Failed decoding dbAdditionalInfo")
		// }
		// ccCustomerID, err := base64.StdEncoding.DecodeString(dbCustomerID)
		// if err != nil {
		// 	return nil, errors.New("Failed decoding dbCustomerID")
		// }
		// ccTypes, err := base64.StdEncoding.DecodeString(dbType)
		// if err != nil {
		// 	return nil, errors.New("Failed decoding dbType")
		// }
		// ccName, err := base64.StdEncoding.DecodeString(dbName)
		// if err != nil {
		// 	return nil, errors.New("Failed decoding dbName")
		// }
		// ccSearchText, err := base64.StdEncoding.DecodeString(dbSearchText)
		// if err != nil {
		// 	return nil, errors.New("Failed decoding dbSearchText")
		// }
		// ccTenantID, err := base64.StdEncoding.DecodeString(dbTenantID)
		// if err != nil {
		// 	return nil, errors.New("Failed decoding dbTenantID")
		// }

		ok, err := stub.InsertRow("device", shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: ccID}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: ccAdditionalInfo}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: ccCustomerID}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: ccTypes}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: ccName}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: ccSearchText}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: ccTenantID}}},
		})

		if !ok && err == nil {
			return nil, errors.New("device table was already made")
		}
	}

	// Migrate Complete
	myLogger.Debugf("device Migrate ... Done")

	rows, err = db.Query("SELECT id, credentials_id, credentials_type, credentials_value, device_id from device_credentials")
	if err != nil {
		return nil, errors.New("Can't get device_credentials table")
	}
	defer rows.Close()

	// var dbID string
	var dbCredentialsID string
	var dbCredentialsType string
	var dbCredentialsValue string
	var dbDeviceID string
	var ccCredentialsID []byte
	var ccCredentialsType []byte
	var ccCredentialsValue []byte
	var ccDeviceID []byte
	for rows.Next() {
		err := rows.Scan(&dbID, &dbCredentialsID, &dbCredentialsType, &dbCredentialsValue, &dbDeviceID)
		if err != nil {
			return nil, errors.New("Can't get device_credentials table rows")
		}

		ccID = dbID
		ccCredentialsID = []byte(dbCredentialsID)
		ccCredentialsType = []byte(dbCredentialsType)
		ccCredentialsValue = []byte(dbCredentialsValue)
		ccDeviceID = []byte(dbDeviceID)
		// ccCredentialsID, err := base64.StdEncoding.DecodeString(dbCredentialsID)
		// if err != nil {
		// 	return nil, errors.New("Failed decoding dbCredentialsID")
		// }
		// ccCredentialsType, err := base64.StdEncoding.DecodeString(dbCredentialsType)
		// if err != nil {
		// 	return nil, errors.New("Failed decoding dbCredentialsType")
		// }
		// ccCredentialsValue, err := base64.StdEncoding.DecodeString(dbCredentialsValue)
		// if err != nil {
		// 	return nil, errors.New("Failed decoding dbCredentialsValue")
		// }
		// ccDeviceID, err := base64.StdEncoding.DecodeString(dbDeviceID)
		// if err != nil {
		// 	return nil, errors.New("Failed decoding dbDeviceID")
		// }

		ok, err := stub.InsertRow("deviceCredentials", shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: ccID}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: ccCredentialsID}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: ccCredentialsType}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: ccCredentialsValue}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: ccDeviceID}}},
		})

		if !ok && err == nil {
			return nil, errors.New("device_credentials table was already made")
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

	if function != "query" {
		return nil, errors.New("Invalid query function name. Expecting 'query' but found '" + function + "'")
	}

	var err error

	if len(args) != 1 {
		myLogger.Debug("Incorrect number of arguments. Expecting name of an asset to query")
		return nil, errors.New("Incorrect number of arguments. Expecting name of an asset to query")
	}

	tableName := args[0]

	myLogger.Debugf("Arg [%s]", string(tableName))

	// myTable, err := stub.GetTable(tableName)
	// if err != nil {
	// 	myLogger.Debugf("Failed get table [%s]: [%s]", string(tableName), err)
	// 	return nil, fmt.Errorf("Failed get table [%s]: [%s]", string(tableName), err)
	// }

	// myTableName, err := base64.StdEncoding.DecodeString(myTable.Name)
	// if err != nil {
	// 	return nil, errors.New("Failed decoding myTableName")
	// }

	ccTestID := "1e91e194d6681d0b358897730171392"

	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: string(ccTestID)}}
	columns = append(columns, col1)

	row, err := stub.GetRow(tableName, columns)
	if err != nil {
		myLogger.Debugf("Failed get data [%s]: [%s]", string(tableName), err)
		return nil, fmt.Errorf("Failed  get data [%s]: [%s]", string(tableName), err)
	}

	// row, err := stub.GetRow("device", columns)
	// if err != nil {
	// 	myLogger.Debugf("Failed get data [%s]: [%s]", string(myTable.Name), err)
	// 	return nil, fmt.Errorf("Failed  get data [%s]: [%s]", string(myTable.Name), err)
	// }

	myLogger.Debugf("Query done [% x]", row.Columns[4].GetBytes())

	return row.Columns[4].GetBytes(), nil

	// return myTableName, nil
}

func main() {
	primitives.SetSecurityLevel("SHA3", 256)
	err := shim.Start(new(AssetManagementChaincode))
	if err != nil {
		fmt.Printf("Error starting AssetManagementChaincode: %s", err)
	}
}
