package ghostrace

import (
	"syscall"
)

func TracePid(pid int) (chan *Syscall, error) {
	ret := make(chan *Syscall)
	if err := syscall.PtraceAttach(pid); err != nil {
		return nil, err
	}
	go func() {
		for {

		}
		close(ret)
	}()
	return ret, nil
}
