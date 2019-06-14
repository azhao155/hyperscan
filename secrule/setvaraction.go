package secrule

type setvarAction struct {
	parameter string
}

func newSetvarAction(parameter string) *setvarAction {
	return &setvarAction{parameter: parameter}
}

func (sv *setvarAction) Execute() (err error) {
	//TODO: implementation goes here
	return nil
}