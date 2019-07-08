package secrule

// ActionHandler handles SecRule actions
type actionHandler interface {
	isDisruptive() bool
	execute(envMap) *actionResult
}
