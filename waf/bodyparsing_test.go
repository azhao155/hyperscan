package waf

import (
	"testing"
)

func TestMediaTypeStructsInSync(t *testing.T) {
	if int(_lastReqBodyTypes) != len(ReqBodyTypeStrings) {
		t.Fatalf("int(_lastReqBodyTypes) != len(ReqBodyTypeStrings)")
	}
}
