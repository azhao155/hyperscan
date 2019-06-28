package secrule

// RulePredicate that determines the action to be taken
type RulePredicate struct {
	Targets       []string
	ExceptTargets []string // ExceptTargets are the targets that are exempt/excluded from being matched.
	Op            Operator
	OpFunc        operatorFunc
	Neg           bool
	Val           string
}

//example to show usage - subject to change as other components get written
func (rp *RulePredicate) eval(content map[string]string) (bool, string, error) {
	for _, target := range rp.Targets {
		result, output, err := rp.OpFunc(content[target], rp.Val)
		if err != nil {
			return result, "", err
		}

		if rp.Neg {
			result = !result
		}

		if result {
			return result, output, nil
		}
	}

	return false, "", nil
}
