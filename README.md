Web application firewall used by Azure Application Gateway.

If you are using this repo as a submodule of Networking-AppGw, then you can
simply use the AppGw dev container. Else, if you want to run this repo
standalone, then use the following commands for container management:
```
# Automatically build and run the dev container
docker-compose run --rm --service-ports --name azwafdev azwafdev

# If you get errors about an existing container with the same name, delete existing containers first
docker container prune -f
docker network prune -f

# To force rebuild of container image
docker-compose build --no-cache azwafdev
```

Within the container you can run the following commands:
```
# To run the main server in standalone mode
go run azwaf/cmd/server -secruleconf=secrule/rulesetfiles/crs3.0/main.conf -loglevel=info

# To run all tests
go test -cover azwaf/...

# To wait for a remote debugger to attach and debug tests
dlv test --api-version=2 --headless --listen=:2345 "azwaf/somepackage" -- -test.run TestSomeFunction

# To wait for a remote debugger to attach to the main function in standalone mode
dlv debug --api-version=2 --headless --listen=:2345 "azwaf/cmd/server" -- -secruleconf=secrule/rulesetfiles/crs3.0/main.conf -loglevel=info

# To run all CRS regression tests
RUN_CRS_REGRESSION_TESTS=1 go test azwaf/integrationtesting -run TestCrsRules

# To run CRS regression tests for a specific rule
RUN_CRS_REGRESSION_TESTS=1 go test azwaf/integrationtesting -run TestCrsRules --ruleID=941100

# To run code style analysis
go install golang.org/x/lint/golint
./stylechecks.sh

# To generate a detailed code coverage report
go test -count=1 -covermode=count -coverprofile=coverage.out azwaf/...
go tool cover -html=coverage.out -o coverage.html

# To regenerate the gRPC stubs
protoc -I./proto/ waf.proto --go_out=plugins=grpc:proto
```

Use the Grpcurl tool to manually test Azwaf's gRPC API:
```
go install github.com/fullstorydev/grpcurl/cmd/grpcurl

go run azwaf/cmd/server -loglevel=info

grpcurl -plaintext 127.0.0.1:37291 describe

grpcurl -plaintext -d @ 127.0.0.1:37291 wafservice.WafService/PutConfig <<EOF
{
  "configVersion": 1,
  "metaData": {
    "resourceID": "/some/resource",
    "instanceID": "appgw_123"
  },
  "policyConfigs": [
    {
      "configID": "myconfig1",
      "isDetectionMode": false,
      "customRuleConfig": {
        "customRules": [
          {
            "name": "rule1",
            "priority": 100,
            "ruleType": "MatchRule",
            "matchConditions": [
              {
                "matchVariables": [
                  {
                    "variableName": "RequestUri",
                    "selector": ""
                  }
                ],
                "operator": "Contains",
                "negateCondition": false,
                "matchValues": [
                  "helloworld"
                ],
                "transforms": [
                  "Lowercase"
                ]
              }
            ],
            "action": "Block"
          }
        ]
      }
    }
  ]
}
EOF

grpcurl -plaintext -d @ 127.0.0.1:37291 wafservice.WafService/EvalRequest <<EOF
{
  "headersAndFirstChunk": {
    "transactionID": "abc123",
    "remoteAddr": "1.2.3.4",
    "configID": "myconfig1",
    "metaData": {
      "scope": "",
      "scopeName": ""
    },
    "method": "POST",
    "uri": "/?a=helloworld",
    "protocol": "HTTP/1.1",
    "headers": [
      {
        "key": "Host",
        "value": "example.com"
      },
      {
        "key": "Content-Type",
        "value": "application/x-www-form-urlencoded"
      },
      {
        "key": "User-Agent",
        "value": "someagent/1.0.0"
      },
      {
        "key": "Content-Length",
        "value": "123"
      },
      {
        "key": "Accept",
        "value": "*/*"
      }
    ],
    "firstBodyChunk": "YWJjPWRlJmI9Mg==",
    "moreBodyChunks": false
  }
}
EOF
```
