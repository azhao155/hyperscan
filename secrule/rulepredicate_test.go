package secrule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVarCounting(t *testing.T) {
	assert := assert.New(t)

	rp := RulePredicate{
		Targets: []Target{{Name: "TX", Selector: "1", IsCount: true}},
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
