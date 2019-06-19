package secrule

// ActionHandler handles SecRule actions
type actionHandler interface {
	Execute(perRequestState envMap) (err error)
}
