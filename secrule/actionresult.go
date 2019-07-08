package secrule

type actionResult struct {
	allow      bool
	statusCode int
	err        error
}

func newActionResult() *actionResult {
	return &actionResult{true, 200, nil}
}
