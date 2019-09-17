package customrule

import (
	"azwaf/secrule"
	"azwaf/waf"
	"sort"

	"github.com/rs/zerolog"
)

// RuleLoader obtains rules from customer specified format
type RuleLoader interface {
	GetSecRules(logger zerolog.Logger, config waf.CustomRuleConfig) (rules []secrule.Statement, err error)
}

type ruleLoader struct {
	geoDB waf.GeoDB
}

// NewCustomRuleLoader loads custom rules.
func NewCustomRuleLoader(geoDB waf.GeoDB) RuleLoader {
	return &ruleLoader{geoDB: geoDB}
}

func (rl *ruleLoader) GetSecRules(logger zerolog.Logger, config waf.CustomRuleConfig) (rules []secrule.Statement, err error) {
	cc := rl.loadCustomRules(logger, config)
	if err != nil {
		return
	}

	var st secrule.Statement
	for _, cr := range cc {
		st, err = rl.toSecRule(cr)
		if err != nil {
			return
		}

		rule := st.(*secrule.Rule)
		rules = append(rules, rule)
	}

	logger.Printf("Successfully converted custom rules into %d sec rules", len(rules))
	return
}

func (rl *ruleLoader) loadCustomRules(logger zerolog.Logger, config waf.CustomRuleConfig) (rules []waf.CustomRule) {
	rules = config.CustomRules()

	// Priority determines the order of execution, no two rules have the same priority.
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority() < rules[j].Priority()
	})

	return
}
