package ghostrace

import (
	"fmt"

	"./process"
	"./sys"
)

type Event struct {
	Process process.Process
	Syscall sys.Syscall
}

func (e *Event) String() string {
	return fmt.Sprintf("[pid %d] %s", e.Process.Pid(), e.Syscall)
}
