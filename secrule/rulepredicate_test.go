package secrule

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVarCounting(t *testing.T) {
	assert := assert.New(t)

	rp := RulePredicate{
		Targets: []string{"&TX:1"},
		Op:      Gt,
		Val:     "0",
	}

	em := newEnvMap()
	result, _, err := rp.eval(em)
	assert.Nil(err)
	assert.False(result)

	em.set("tx.1", &stringObject{Value: "v1"})
	result, _, err = rp.eval(em)
	assert.Nil(err)
	assert.True(result)
}
