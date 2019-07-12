package secrule

// Statement is a SecRule-lang statement, such as SecRule, SecAction, SecMarker, etc.
type Statement interface{}

// ActionStmt represents a SecAction in the SecRule-lang.
type ActionStmt struct {
	ID         int
	Msg        string
	RawActions []RawAction
	Actions    []actionHandler
	Nolog      bool
}

// Rule is one or more SecRule statements in the SecRule-lang. Multiple SecRules if they are chained.
type Rule struct {
	ID    int
	Items []RuleItem
	Nolog bool
}

// RuleItem is a single SecRule statement, which might be part of a chain.
type RuleItem struct {
	Msg             string
	Predicate       RulePredicate
	RawActions      []RawAction
	Actions         []actionHandler
	Transformations []Transformation
	PmPhrases       []string
}

// RawAction is a key-value pair in the "actions"-block of a SecRule.
type RawAction struct {
	Key string
	Val string
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
	Utf8toUnicode
)
