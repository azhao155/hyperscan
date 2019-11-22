package secrule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVarCounting(t *testing.T) {
	assert := assert.New(t)

	target := Target{Name: "TX", Selector: "1", IsCount: true}
	rp := RulePredicate{
		Targets: []Target{target},
		Op:      Gt,
		Val:     "0",
	}

	em := newEnvironment(&ScanResults{})
	sr := &ScanResults{targetsCount: make(map[Target]int)}
	result, _, err := rp.eval(target, sr, em)
	assert.Nil(err)
	assert.False(result)

	em.set("tx.1", &stringObject{Value: "v1"})
	result, _, err = rp.eval(target, sr, em)
	assert.Nil(err)
	assert.True(result)
}

func TestVarGt(t *testing.T) {
	// Arrange
	assert := assert.New(t)

	target := Target{Name: "TX", Selector: "somevar"}
	rp := RulePredicate{
		Targets: []Target{target},
		Op:      Gt,
		Val:     "4",
	}

	em := newEnvironment(&ScanResults{})
	sr := &ScanResults{targetsCount: make(map[Target]int)}

	// Act
	result1, _, err1 := rp.eval(target, sr, em)
	em.set("tx.somevar", &integerObject{Value: 3})
	result2, _, err2 := rp.eval(target, sr, em)
	em.set("tx.somevar", &integerObject{Value: 5})
	result3, _, err3 := rp.eval(target, sr, em)

	// Assert
	assert.NotNil(err1)
	assert.False(result1)
	assert.Nil(err2)
	assert.False(result2)
	assert.Nil(err3)
	assert.True(result3)
}
