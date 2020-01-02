package ruleevaluation

import (
	. "azwaf/secrule"
	. "azwaf/secrule/ast"

	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVarCounting(t *testing.T) {
	assert := assert.New(t)

	target := Target{Name: TargetTx, Selector: "1", IsCount: true}
	rp := RulePredicate{
		Targets: []Target{target},
		Op:      Gt,
		Val:     Value{IntToken(0)},
	}

	em := NewEnvironment(nil)
	sr := &ScanResults{TargetsCount: make(map[Target]int)}
	result, _, err := eval(rp, target, nil, sr, em)
	assert.Nil(err)
	assert.False(result)

	em.Set(EnvVarTx, "1", Value{StringToken("v1")})
	result, _, err = eval(rp, target, nil, sr, em)
	assert.Nil(err)
	assert.True(result)
}

func TestVarGt(t *testing.T) {
	// Arrange
	assert := assert.New(t)

	target := Target{Name: TargetTx, Selector: "somevar"}
	rp := RulePredicate{
		Targets: []Target{target},
		Op:      Gt,
		Val:     Value{IntToken(4)},
	}

	em := NewEnvironment(nil)
	sr := &ScanResults{TargetsCount: make(map[Target]int)}

	// Act
	result1, _, err1 := eval(rp, target, nil, sr, em)
	em.Set(EnvVarTx, "somevar", Value{IntToken(3)})
	result2, _, err2 := eval(rp, target, nil, sr, em)
	em.Set(EnvVarTx, "somevar", Value{IntToken(5)})
	result3, _, err3 := eval(rp, target, nil, sr, em)

	// Assert
	assert.NotNil(err1)
	assert.False(result1)
	assert.Nil(err2)
	assert.False(result2)
	assert.Nil(err3)
	assert.True(result3)
}
