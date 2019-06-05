package secrule

// ActionHandler handles SecRule actions
type actionHandler interface {
	Execute() (err error)
}
