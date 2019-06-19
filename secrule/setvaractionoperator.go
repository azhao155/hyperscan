package secrule

import "fmt"

type setvarActionOperator int

const (
	set setvarActionOperator = iota
	increment
	decrement
	deleteVar
)

func toSetvarOperator(opStr string) (setvarActionOperator, error) {
	switch opStr {
	case "=":
		return set, nil
	case "=+":
		return increment, nil
	case "=-":
		return decrement, nil
	case "!":
		return deleteVar, nil
	}

	return -1, fmt.Errorf("Unsupported operator %s", opStr)
}
