package ruleevaluation

import (
	. "azwaf/secrule/ast"

	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectSQLiOperator(t *testing.T) {
	assert := assert.New(t)
	found, output, err := detectSQLiOperatorEval(Value{StringToken("--1 UNION ALL SELECT * FROM FOO")}, Value{StringToken("")})
	assert.Nil(err)
	assert.True(found, "SQLI not detected")
	var expected = "1UEok"
	assert.Equal(expected, output, "Fingerprints do not match")
}

func TestDetectXSSOperator(t *testing.T) {
	assert := assert.New(t)
	found, output, err := detectXSSOperatorEval(Value{StringToken("<script>")}, Value{StringToken("")})
	assert.Nil(err)
	assert.True(found, "XSS not detected")
	var expected = ""
	assert.Equal(expected, output)
}

func TestEqualOperatorEval(t *testing.T) {
	assert := assert.New(t)
	result, _, err := equalOperatorEval(Value{IntToken(5)}, Value{IntToken(5)})
	assert.Nil(err)
	assert.True(result)

	result, _, err = equalOperatorEval(Value{IntToken(5)}, Value{IntToken(-5)})
	assert.Nil(err)
	assert.False(result)
}

func TestGreaterOrEqualOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := greaterOrEqualOperatorEval(Value{IntToken(7)}, Value{IntToken(5)})
	assert.Nil(err)
	assert.True(result)

	result, _, err = greaterOrEqualOperatorEval(Value{IntToken(7)}, Value{IntToken(7)})
	assert.Nil(err)
	assert.True(result)

	result, _, err = greaterOrEqualOperatorEval(Value{IntToken(4)}, Value{IntToken(5)})
	assert.Nil(err)
	assert.False(result)
}

func TestGreaterThanOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := greaterThanOperatorEval(Value{IntToken(7)}, Value{IntToken(5)})
	assert.Nil(err)
	assert.True(result)

	result, _, err = greaterThanOperatorEval(Value{IntToken(7)}, Value{IntToken(7)})
	assert.Nil(err)
	assert.False(result)

	result, _, err = greaterThanOperatorEval(Value{IntToken(4)}, Value{IntToken(5)})
	assert.Nil(err)
	assert.False(result)
}

func TestLessOrEqualOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := lessOrEqualOperatorEval(Value{IntToken(4)}, Value{IntToken(5)})
	assert.Nil(err)
	assert.True(result)

	result, _, err = lessOrEqualOperatorEval(Value{IntToken(7)}, Value{IntToken(7)})
	assert.Nil(err)
	assert.True(result)

	result, _, err = lessOrEqualOperatorEval(Value{IntToken(6)}, Value{IntToken(5)})
	assert.Nil(err)
	assert.False(result)
}

func TestLessThanOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := lessThanOperatorEval(Value{IntToken(3)}, Value{IntToken(5)})
	assert.Nil(err)
	assert.True(result)

	result, _, err = lessThanOperatorEval(Value{IntToken(7)}, Value{IntToken(7)})
	assert.Nil(err)
	assert.False(result)

	result, _, err = lessThanOperatorEval(Value{IntToken(7)}, Value{IntToken(5)})
	assert.Nil(err)
	assert.False(result)
}

func TestBeginsWithOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := beginsWithOperatorEval(Value{StringToken("abc")}, Value{StringToken("ab")})
	assert.Nil(err)
	assert.True(result)

	result, _, err = beginsWithOperatorEval(Value{StringToken("abc")}, Value{StringToken("de")})
	assert.Nil(err)
	assert.False(result)
}

func TestEndsWithOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := endsWithOperatorEval(Value{StringToken("abc")}, Value{StringToken("bc")})
	assert.Nil(err)
	assert.True(result)

	result, _, err = endsWithOperatorEval(Value{StringToken("bac")}, Value{StringToken("de")})
	assert.Nil(err)
	assert.False(result)
}

func TestContainsOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := containsOperatorEval(Value{StringToken("abcd")}, Value{StringToken("bc")})
	assert.Nil(err)
	assert.True(result)

	result, _, err = containsOperatorEval(Value{StringToken("abcd")}, Value{StringToken("de")})
	assert.Nil(err)
	assert.False(result)
}

func TestContainsWordOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := containsWordOperatorEval(Value{StringToken("a bc d")}, Value{StringToken("bc")})
	assert.Nil(err)
	assert.True(result)

	result, _, err = containsWordOperatorEval(Value{StringToken("abcd")}, Value{StringToken("bc")})
	assert.Nil(err)
	assert.False(result)
}

func TestStreqWordOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := strEqOperatorEval(Value{StringToken("a bc d")}, Value{StringToken("a bc d")})
	assert.Nil(err)
	assert.True(result)

	result, _, err = strEqOperatorEval(Value{StringToken("a bc d")}, Value{StringToken("abcd")})
	assert.Nil(err)
	assert.False(result)
}

func TestWordListSearchOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := wordListSearchOperatorEval(Value{StringToken("ab")}, Value{StringToken("ab cd")})
	assert.Nil(err)
	assert.True(result)

	result, _, err = wordListSearchOperatorEval(Value{StringToken("ab")}, Value{StringToken("abc abcd")})
	assert.Nil(err)
	assert.False(result)
}
