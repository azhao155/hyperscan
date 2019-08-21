package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCustomRuleEngineEvalRequest(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	c := &engineImpl{
		underlyingSecRuleEngine: &mockSecRuleEngine{},
	}

	req := &mockWafHTTPRequest{}
	ev := c.NewEvaluation(logger, req)

	err := ev.ScanHeaders()
	assert.Nil(err)

	assert.True(ev.EvalRules())
}

type mockSecRuleEngine struct{}

func (s *mockSecRuleEngine) NewEvaluation(logger zerolog.Logger, req waf.HTTPRequest) waf.SecRuleEvaluation {
	return &mockSecRuleEvaluation{}
}

type mockSecRuleEvaluation struct{}

func (s *mockSecRuleEvaluation) ScanHeaders() error {
	return nil
}

func (s *mockSecRuleEvaluation) ScanBodyField(contentType waf.ContentType, fieldName string, data string) error {
	return nil
}

func (s *mockSecRuleEvaluation) EvalRules() bool {
	return true
}
