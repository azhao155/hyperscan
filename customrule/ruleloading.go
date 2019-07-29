package customrule

import (
	"azwaf/secrule"
	"encoding/json"
	"github.com/rs/zerolog"
	"sort"
)

// RuleLoader obtains rules from customer specified format
type RuleLoader interface {
	GetSecRules(logger zerolog.Logger, jsonStr string) (rules []secrule.Statement, err error)
}

type ruleLoader struct {
}

func (r *ruleLoader) GetSecRules(logger zerolog.Logger, jsonStr string) (rules []secrule.Statement, err error) {
	logger.Printf("Parsing incoming JSON custom rule string %s", jsonStr)
	cc, err := r.loadCustomRules(logger, jsonStr)
	if err != nil {
		return
	}

	var st secrule.Statement
	for _, cr := range cc {
		st, err = cr.toSecRule()
		if err != nil {
			return
		}

		rule := st.(*secrule.Rule)
		rules = append(rules, rule)
	}

	logger.Printf("Successfully converted custom rules into %d sec rules", len(rules))
	return
}

func (r *ruleLoader) loadCustomRules(logger zerolog.Logger, jsonStr string) (rules []CustomRule, err error) {
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
