package ghostrace

import (
	"./process"
)

type Syscall struct {
	Process process.Process
	Num     int
	Name    string
	Args    []uint64
}
