package secrule

// Statement is a SecRule-lang statement, such as SecRule, SecAction, SecMarker, etc.
type Statement interface{}

// ActionStmt represents a SecAction in the SecRule-lang.
type ActionStmt struct {
	ID      int
	Phase   int
	Actions []Action
}

// Rule is one or more SecRule statements in the SecRule-lang. Multiple SecRules if they are chained.
type Rule struct {
	ID    int
	Phase int
	Items []RuleItem
}

// RuleItem is a single SecRule statement, which might be part of a chain.
type RuleItem struct {
	Predicate       RulePredicate
	Actions         []Action
	Transformations []Transformation
	PmPhrases       []string
}

// RulePredicate that determines whether a rule is triggered.
type RulePredicate struct {
	Targets         []Target
	ExceptTargets   []Target // ExceptTargets are the targets that are exempt/excluded from being matched.
	Op              Operator
	Neg             bool
	Val             string // TODO potential optimization: this could be object (or there could be an IntVal field), so for integers there will be much fewer string to int conversions
	valMacroMatches [][]string
}

// Target describes which field of the request we want to be scanning.
type Target struct {
	Name            string // Example value: ARGS
	Selector        string // Example value: streetAddress
	IsRegexSelector bool   // Example of target where this is true: ARGS:/hel*o/
	IsCount         bool   // Example of target where this is true, meaning number of args: &ARGS
}

// Action is any of the items in the actions-block of a SecRule or SecAction.
type Action interface{}

// RawAction is an action we couldn't parse into anything more specific.
type RawAction struct {
	Key string
	Val string
}

// AllowAction is an action that instructs to stop processing and allow the request.
type AllowAction struct{}

// BlockAction is an action that instructs to block the request based on the definition of SecDefaultAction.
type BlockAction struct{}

// DenyAction is an action that instructs to stop processing and deny the request.
type DenyAction struct{}

// NoLogAction is an action that makes the engine not log.
type NoLogAction struct{}

// LogAction is an action that makes the engine log. It logs by default, but this action is useful to override NoLogAction.
type LogAction struct{}

// MsgAction is an action that says what message to log.
type MsgAction struct {
	Msg string
}

// SkipAfterAction instructs to skip all subsequent statements until the SecMarker with the given label is found.
type SkipAfterAction struct {
	Label string
}

// SetVarAction is the action that modifies variables in the per-request environment.
type SetVarAction struct {
	// TODO potential optimization, variable and value could be stored as a list of objects (especially in case of macros)
	variable        string
	operator        setvarActionOperator
	value           string
	varMacroMatches [][]string
	valMacroMatches [][]string
}

// Operator that the SecRule will use to evaluates the input against the value.
type Operator int

// Operators that SecRules can use.
const (
	_ Operator = iota
	BeginsWith
	EndsWith
	Contains
	ContainsWord
	DetectSQLi
	DetectXSS
	Eq
	Ge
	Gt
	Le
	Lt
	Pm
	Pmf
	PmFromFile
	Rx
	Streq
	Strmatch
	ValidateByteRange
	ValidateURLEncoding
	ValidateUtf8Encoding
	Within
	GeoLookup
	IPMatch
	IPMatchFromFile
	Rbl
)

// Transformation is what will be applied to the input before it is evaluated against the operator/input of the rule.
type Transformation int

// Transformation that SecRules can use.
const (
	_ Transformation = iota
	CmdLine
	CompressWhitespace
	CSSDecode
	HexEncode
	HTMLEntityDecode
	JsDecode
	Length
	Lowercase
	None
	NormalisePath
	NormalisePathWin
	NormalizePath
	NormalizePathWin
	RemoveComments
	RemoveNulls
	RemoveWhitespace
	ReplaceComments
	Sha1
	URLDecode
	URLDecodeUni
	URLEncode
	Utf8toUnicode
	Trim
)

// Marker is a SecMarker, used by skipAfter-actions.
type Marker struct {
	Label string
}
