package secrule

// Rule represents a SecRule, or multiple SecRules if they are chained.
type Rule struct {
	ID    int
	Items []RuleItem
}

// RuleItem represents a SecRule.
type RuleItem struct {
	Msg             string
	Predicate       RulePredicate
	RawActions      []RawAction
	Actions         []actionHandler
	Transformations []Transformation
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
