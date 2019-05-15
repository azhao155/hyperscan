package secrule

type rule struct {
	ID    int
	Items []ruleItem
}

type ruleItem struct {
	Msg             string
	Targets         []string
	Op              operator
	Neg             bool
	Val             string
	RawActions      []rawAction
	Transformations []transformation
}

type rawAction struct {
	Key string
	Val string
}

type operator int

const (
	_ operator = iota
	beginsWith
	endsWith
	contains
	containsWord
	detectSQLi
	detectXSS
	eq
	ge
	gt
	lt
	pm
	pmf
	pmFromFile
	rx
	streq
	strmatch
	validateByteRange
	validateUrlEncoding
	validateUtf8Encoding
	within
	geoLookup
	ipMatch
	rbl
)

type transformation int

const (
	_ transformation = iota
	cmdLine
	compressWhitespace
	cssDecode
	hexEncode
	htmlEntityDecode
	jsDecode
	length
	lowercase
	normalisePath
	normalisePathWin
	normalizePath
	normalizePathWin
	removeComments
	removeNulls
	removeWhitespace
	replaceComments
	sha1
	urlDecode
	urlDecodeUni
	utf8toUnicode
)
