import json
import requests


def send_deploy():
    try:
        response = requests.post(
            url="http://203.253.21.91:7050/chaincode",
            headers={
                "Content-Type": "text/plain; charset=utf-8",
            },
            data="{ \
                    \"jsonrpc\": \"2.0\", \
                    \"method\": \"deploy\", \
                    \"params\": { \
                        \"type\": 1, \
                        \"chaincodeID\":{ \
                            \"path\": \"github.com/sung-il/chaincode\" \
                        }, \
                        \"ctorMsg\": { \
                            \"args\":[\"init\"] \
                        }, \
                        \"secureContext\": \"lukas\" \
                    }, \
                    \"id\": 1 \
                    }"
        )
        print('Response HTTP Status Code: {status_code}'.format(
            status_code=response.status_code))
        print('Response HTTP Response Body: {content}'.format(
            content=response.content))
    except requests.exceptions.RequestException:
        print('HTTP Request failed')

    if response.status_code != 200:
        print("This isn't correct status code")
        return

    response = json.loads(response.content)

    return response


def send_invoke(res):
    try:
        print(res["result"])
        print(type(res["result"]["message"]))
        response = requests.post(
            url="http://203.253.21.91:7050/chaincode",
            headers={
                "Content-Type": "text/plain; charset=utf-8",
            },
            data="{ \
                    \"jsonrpc\": \"2.0\", \
                    \"method\": \"invoke\", \
                    \"params\": { \
                        \"type\": 1, \
                        \"chaincodeID\":{ \
                            \"name\": \"%s\" \
                        }, \
                        \"ctorMsg\": { \
                            \"args\":[\"migrate\"] \
                        },  \
                        \"secureContext\": \"lukas\" \
                    }, \
                    \"id\": 3 \
                    }" % (res["result"]["message"])
        )
        print('Response HTTP Status Code: {status_code}'.format(
            status_code=response.status_code))
        print('Response HTTP Response Body: {content}'.format(
            content=response.content))
    except requests.exceptions.RequestException:
        print('HTTP Request failed')


def send_query(res):
    try:
        print(res["result"]["message"])
        response = requests.post(
            url="http://203.253.21.91:7050/chaincode",
            headers={
                "Content-Type": "text/plain; charset=utf-8",
            },
            data="{ \
                    \"jsonrpc\": \"2.0\", \
                    \"method\": \"query\", \
                    \"params\": { \
                        \"type\": 1, \
                        \"chaincodeID\":{ \
                            \"name\": \"%s\" \
                        }, \
                        \"ctorMsg\": { \
                            \"args\":[\"keys\"] \
                        }, \
                        \"secureContext\": \"lukas\" \
                    }, \
                    \"id\": 3 \
                    }" % (res["result"]["message"])
        )
        print('Response HTTP Status Code: {status_code}'.format(
            status_code=response.status_code))
        print('Response HTTP Response Body: {content}'.format(
            content=response.content))
    except requests.exceptions.RequestException:
        print('HTTP Request failed')


while True:
    s = raw_input()
    if not s:
        break
    if s == "deploy":
        deploy_res = send_deploy()
    elif s == "invoke":
        invoke_res = send_invoke(deploy_res)
    elif s == "query":
        query_res = send_query(deploy_res)
