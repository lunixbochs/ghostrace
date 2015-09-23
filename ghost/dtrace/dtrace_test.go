package dtrace

import (
	"fmt"
	"testing"
)

func TestDtrace(t *testing.T) {
	d, err := NewDtrace()
	if err != nil {
		t.Fatal(err)
	}
	if d.Version() == "" {
		t.Fatal("Dtrace.Version() is empty.")
	}
}
