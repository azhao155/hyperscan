package secrule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectSQLiOperator(t *testing.T) {
	assert := assert.New(t)
	found, output, err := detectSQLiOperatorEval("--1 UNION ALL SELECT * FROM FOO", "")
	assert.Nil(err)
	assert.True(found, "SQLI not detected")
	var expected = "1UEok"
	assert.Equal(expected, output, "Fingerprints do not match")
}

func TestDetectXSSOperator(t *testing.T) {
	assert := assert.New(t)
	found, output, err := detectXSSOperatorEval("<script>", "")
	assert.Nil(err)
	assert.True(found, "XSS not detected")
	var expected = ""
	assert.Equal(expected, output)
}

func TestEqualOperatorEval(t *testing.T) {
	assert := assert.New(t)
	result, _, err := equalOperatorEval("5", "5")
	assert.Nil(err)
	assert.True(result)

	result, _, err = equalOperatorEval("5", "-5")
	assert.Nil(err)
	assert.False(result)
}

func TestGreaterOrEqualOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := greaterOrEqualOperatorEval("7", "5")
	assert.Nil(err)
	assert.True(result)

	result, _, err = greaterOrEqualOperatorEval("7", "7")
	assert.Nil(err)
	assert.True(result)

	result, _, err = greaterOrEqualOperatorEval("4", "5")
	assert.Nil(err)
	assert.False(result)
}

func TestGreaterThanOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := greaterThanOperatorEval("7", "5")
	assert.Nil(err)
	assert.True(result)

	result, _, err = greaterThanOperatorEval("4", "5")
	assert.Nil(err)
	assert.False(result)
}

func TestLessOrEqualOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := lessOrEqualOperatorEval("4", "5")
	assert.Nil(err)
	assert.True(result)

	result, _, err = lessOrEqualOperatorEval("7", "7")
	assert.Nil(err)
	assert.True(result)

	result, _, err = lessOrEqualOperatorEval("6", "5")
	assert.Nil(err)
	assert.False(result)
}

func TestLessThanOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := lessThanOperatorEval("3", "5")
	assert.Nil(err)
	assert.True(result)

	result, _, err = lessThanOperatorEval("7", "5")
	assert.Nil(err)
	assert.False(result)
}

func TestBeginsWithOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := beginsWithOperatorEval("abc", "ab")
	assert.Nil(err)
	assert.True(result)

	result, _, err = beginsWithOperatorEval("abc", "de")
	assert.Nil(err)
	assert.False(result)
}

func TestEndsWithOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := endsWithOperatorEval("abc", "bc")
	assert.Nil(err)
	assert.True(result)

	result, _, err = endsWithOperatorEval("abc", "de")
	assert.Nil(err)
	assert.False(result)
}

func TestContainsOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := containsOperatorEval("abcd", "bc")
	assert.Nil(err)
	assert.True(result)

	result, _, err = containsOperatorEval("abcd", "de")
	assert.Nil(err)
	assert.False(result)
}

func TestContainsWordOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := containsWordOperatorEval("a bc d", "bc")
	assert.Nil(err)
	assert.True(result)

	result, _, err = containsWordOperatorEval("abcd", "bc")
	assert.Nil(err)
	assert.False(result)
}

func TestStreqWordOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := strEqOperatorEval("a bc d", "a bc d")
	assert.Nil(err)
	assert.True(result)

	result, _, err = strEqOperatorEval("a bc d", "abcd")
	assert.Nil(err)
	assert.False(result)
}

func TestWordListSearchOperatorEval(t *testing.T) {
	assert := assert.New(t)

	result, _, err := wordListSearchOperatorEval("ab", "ab cd")
	assert.Nil(err)
	assert.True(result)

	result, _, err = wordListSearchOperatorEval("ab", "abc abcd")
	assert.Nil(err)
	assert.False(result)
}
