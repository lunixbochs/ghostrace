package process

import (
	"errors"
	"os"
	"testing"
)

func TestSelf(t *testing.T) {
	pid := os.Getpid()
	p, err := FindPid(pid)
	if err != nil {
		t.Fatal(err)
	}
	if p.Pid() != pid {
		t.Fatal(errors.New("Get(pid) returned wrong process"))
	}
	if p.Parent() == nil {
		t.Fatal(errors.New("Could not find own parent process."))
	}
	children := p.Parent().Children()
	if len(children) == 0 {
		t.Fatal(errors.New("Could not find parent's child processes."))
	}
	selfCheck := children.Filter(func(p Process) bool { return p.Pid() == pid })
	if selfCheck == nil {
		t.Fatal(errors.New("Could not find self in parent's child process list."))
	}
}
