package waf

import (
	"testing"
)

func TestMediaTypeStructsInSync(t *testing.T) {
	if len(ReqBodyTypeToStr) != len(ReqBodyTypeStrings) {
		t.Fatalf("len(ReqBodyTypeToStr) != len(ReqBodyTypeStrings)")
	}

	if int(_lastReqBodyTypes) != len(ReqBodyTypeStrings) {
		t.Fatalf("int(_lastReqBodyTypes) != len(ReqBodyTypeStrings)")
	}

	for i, v := range ReqBodyTypeStrings {
		if i != int(ReqBodyTypeToStr[v]) {
			t.Fatalf("ReqBodyTypeStrings in wrong order")
		}
	}
	for k, v := range ReqBodyTypeToStr {
		if k != ReqBodyTypeStrings[v] {
			t.Fatalf("ReqBodyTypeToStr does not match ReqBodyTypeStrings")
		}
	}
}
