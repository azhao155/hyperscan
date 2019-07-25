package customrule

import (
	"encoding/json"
	"github.com/rs/zerolog"
	"sort"
)

// RuleLoader obtains rules from customer specified format
type RuleLoader interface {
	GetRules(logger zerolog.Logger, jsonStr string) (rules []CustomRule, err error)
}

type ruleLoader struct {
}

func (r *ruleLoader) GetRules(logger zerolog.Logger, jsonStr string) (rules []CustomRule, err error) {
	// Validations are done in NRP.

	err = json.Unmarshal([]byte(jsonStr), &rules)
	if err != nil {
		logger.Error().Err(err).Msg("Error while unmarshaling JSON custom rules")
		return
	}

	// Priority determines the order of execution, no two rules have the same priority.
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	return
}
