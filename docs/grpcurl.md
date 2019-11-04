Use the Grpcurl tool to manually test Azwaf's gRPC API.

Example usage:
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
      "secRuleConfig": {
        "enabled": true,
        "ruleSetId": "OWASP CRS 3.0"
      },
      "ipReputationConfig": {
        "enabled": true
      }
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


grpcurl -plaintext -d @ 127.0.0.1:37291 wafservice.WafService/PutIPReputationList <<EOF
{
  "ip": [
    "13.37.0.0/16",
    "42.42.42.0/24"
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
      "scope": "scope1",
      "scopeName": "scopename1"
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
