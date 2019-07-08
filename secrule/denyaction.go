package secrule

// denyAction captures the CRS deny action
type denyAction struct {
}

func newDenyAction() *denyAction {
	return &denyAction{}
}

func (d denyAction) isDisruptive() bool {
	return true
}

// execute performs no action. Deny action is performed by returning a false to NGINX
func (d denyAction) execute(perRequestEnv envMap) (ar *actionResult) {
	return &actionResult{false, 403, nil}
}
