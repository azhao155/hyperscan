package logging

type customerFirewallLogEntry struct {
	TimeStamp     string                           `json:"timeStamp"`
	ResourceID    string                           `json:"resourceId"`
	OperationName string                           `json:"operationName"`
	Category      string                           `json:"category"`
	Properties    customerFirewallLogEntryProperty `json:"properties"`
}

type customerFirewallLimitExceedLogEntry struct {
	TimeStamp     string                                      `json:"timeStamp"`
	ResourceID    string                                      `json:"resourceId"`
	OperationName string                                      `json:"operationName"`
	Category      string                                      `json:"category"`
	Properties    customerFirewallLimitExceedLogEntryProperty `json:"properties"`
}

type customerFirewallBodyParseLogEntry struct {
	TimeStamp     string                                    `json:"timeStamp"`
	ResourceID    string                                    `json:"resourceId"`
	OperationName string                                    `json:"operationName"`
	Category      string                                    `json:"category"`
	Properties    customerFirewallBodyParseLogEntryProperty `json:"properties"`
}

type customerFirewallLogEntryProperty struct {
	InstanceID      string                          `json:"instanceId"`
	ClientIP        string                          `json:"clientIp"`
	ClientPort      string                          `json:"clientPort"`
	RequestURI      string                          `json:"requestUri"`
	RuleSetType     string                          `json:"ruleSetType"`
	RuleSetVersion  string                          `json:"ruleSetVersion"`
	RuleID          string                          `json:"ruleId"`
	RuleGroup       string                          `json:"ruleGroup"`
	Message         string                          `json:"message"`
	Action          string                          `json:"action"`
	Details         customerFirewallLogDetailsEntry `json:"details"`
	Hostname        string                          `json:"hostname"`
	TransactionID   string                          `json:"transactionId"`
	PolicyID        string                          `json:"policyId"`
	PolicyScope     string                          `json:"policyScope"`
	PolicyScopeName string                          `json:"policyScopeName"`
}

type customerFirewallLimitExceedLogEntryProperty struct {
	InstanceID      string `json:"instanceId"`
	ClientIP        string `json:"clientIp"`
	ClientPort      string `json:"clientPort"`
	RequestURI      string `json:"requestUri"`
	RuleSetType     string `json:"ruleSetType"`
	RuleSetVersion  string `json:"ruleSetVersion"`
	Message         string `json:"message"`
	Action          string `json:"action"`
	Hostname        string `json:"hostname"`
	TransactionID   string `json:"transactionId"`
	PolicyID        string `json:"policyId"`
	PolicyScope     string `json:"policyScope"`
	PolicyScopeName string `json:"policyScopeName"`
}

type customerFirewallBodyParseLogEntryProperty struct {
	InstanceID      string                                   `json:"instanceId"`
	ClientIP        string                                   `json:"clientIp"`
	ClientPort      string                                   `json:"clientPort"`
	RequestURI      string                                   `json:"requestUri"`
	RuleSetType     string                                   `json:"ruleSetType"`
	RuleSetVersion  string                                   `json:"ruleSetVersion"`
	Message         string                                   `json:"message"`
	Action          string                                   `json:"action"`
	Details         customerFirewallLogBodyParseDetailsEntry `json:"details"`
	Hostname        string                                   `json:"hostname"`
	TransactionID   string                                   `json:"transactionId"`
	PolicyID        string                                   `json:"policyId"`
	PolicyScope     string                                   `json:"policyScope"`
	PolicyScopeName string                                   `json:"policyScopeName"`
}

type customerFirewallLogDetailsEntry struct {
	Message string `json:"message"`
	Data    string `json:"data"`
	File    string `json:"file"`
	Line    string `json:"line"`
}

type customerFirewallLogBodyParseDetailsEntry struct {
	Message string `json:"message"`
}

type customerFirewallIPReputationLogEntry struct {
	TimeStamp     string                                       `json:"timeStamp"`
	ResourceID    string                                       `json:"resourceId"`
	OperationName string                                       `json:"operationName"`
	Category      string                                       `json:"category"`
	Properties    customerFirewallIPReputationLogEntryProperty `json:"properties"`
}

type customerFirewallIPReputationLogEntryProperty struct {
	InstanceID      string `json:"instanceId"`
	ClientIP        string `json:"clientIp"`
	ClientPort      string `json:"clientPort"`
	RequestURI      string `json:"requestUri"`
	RuleSetType     string `json:"ruleSetType"`
	RuleSetVersion  string `json:"ruleSetVersion"`
	Message         string `json:"message"`
	Action          string `json:"action"`
	Hostname        string `json:"hostname"`
	TransactionID   string `json:"transactionId"`
	PolicyID        string `json:"policyId"`
	PolicyScope     string `json:"policyScope"`
	PolicyScopeName string `json:"policyScopeName"`
}

type customerFirewallCustomRuleLogEntry struct {
	TimeStamp     string                                       `json:"timeStamp"`
	ResourceID    string                                       `json:"resourceId"`
	OperationName string                                       `json:"operationName"`
	Category      string                                       `json:"category"`
	Properties    customerFirewallCustomRuleLogEntryProperties `json:"properties"`
}

type customerFirewallCustomRuleLogEntryProperties struct {
	InstanceID      string `json:"instanceId"`
	ClientIP        string `json:"clientIp"`
	RequestURI      string `json:"requestUri"`
	RuleSetType     string `json:"ruleSetType"`
	RuleID          string `json:"ruleId"`
	Message         string `json:"message"`
	Action          string `json:"action"`
	Hostname        string `json:"hostname"`
	TransactionID   string `json:"transactionId"`
	PolicyID        string `json:"policyId"`
	PolicyScope     string `json:"policyScope"`
	PolicyScopeName string `json:"policyScopeName"`
	Engine          string `json:"engine"`
}
