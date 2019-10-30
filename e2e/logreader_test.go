package e2e

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

const (
	path     = "/appgwroot/log/azwaf/"
	fileName = "waf_json.log"
)

func readLogs(t *testing.T) (lines []string) {
	file, err := ioutil.ReadFile(path + fileName)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
		return
	}
	buf := bytes.NewBuffer(file)
	for {
		line, err := buf.ReadString('\n')
		if len(line) == 0 {
			if err != nil {
				if err == io.EOF {
					break
				} else {
					t.Fatalf("Got unexpected error: %v", err)
				}
				return
			}
		}
		lines = append(lines, line)
		if err != nil && err != io.EOF {
			t.Fatalf("Got unexpected error: %v", err)
			return
		}
	}
	return
}

func clearLogs(t *testing.T) {
	err := os.Truncate(path+fileName, 0)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
}
