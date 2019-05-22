package secrule

type Rule struct {
	ID    int
	Items []RuleItem
}

type RuleItem struct {
	Msg             string
	Targets         []string
	Op              Operator
	Neg             bool
	Val             string
	RawActions      []RawAction
	Transformations []Transformation
}

type RawAction struct {
	Key string
	Val string
}

type Operator int

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
	ValidateUrlEncoding
	ValidateUtf8Encoding
	Within
	GeoLookup
	IpMatch
	Rbl
)

type Transformation int

const (
	_ Transformation = iota
	CmdLine
	CompressWhitespace
	CssDecode
	HexEncode
	HtmlEntityDecode
	JsDecode
	Length
	Lowercase
	NormalisePath
	NormalisePathWin
	NormalizePath
	NormalizePathWin
	RemoveComments
	RemoveNulls
	RemoveWhitespace
	ReplaceComments
	Sha1
	UrlDecode
	UrlDecodeUni
	Utf8toUnicode
)
