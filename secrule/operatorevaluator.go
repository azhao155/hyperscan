package secrule

type operatorEvaluator interface {
	eval(target string, value string) (result bool, output string, err error)
}
