package secrule

type skipAfterAction struct {
	label string
}

func (d skipAfterAction) isDisruptive() bool {
	return false
}

func (d skipAfterAction) execute(perRequestEnv envMap) (ar *actionResult) {
	return newActionResult()
}
