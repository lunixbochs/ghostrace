package ghost

import (
	"fmt"

	"./process"
	"./sys"
)

type Event struct {
	Process process.Process
	Syscall sys.Syscall
	Exit    bool
}

func (e *Event) String() string {
	if e.Exit {
		return fmt.Sprintf("[pid %d] exit", e.Process.Pid())
	}
	return fmt.Sprintf("[pid %d] %s", e.Process.Pid(), e.Syscall)
}
