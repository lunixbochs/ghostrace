package ghostrace

import (
	"fmt"
	"syscall"
)

func TracePid(pid int) (chan *Syscall, error) {
	ret := make(chan *Syscall)
	if err := syscall.PtraceAttach(pid); err != nil {
		return nil, err
	}
	var regs syscall.PtraceRegs
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, 0, nil); err != nil {
		return nil, err
	}
	// TODO: set options for following children?
	if err := syscall.PtraceSetOptions(pid, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
		return nil, err
	}
	go func() {
		newSyscall := true
		for {
			// wait for syscall entry
			if err := syscall.PtraceSyscall(pid, 0); err != nil {
				break
			}
			if _, err := syscall.Wait4(pid, &status, 0, nil); err != nil {
				break
			}
			signal := status.StopSignal()
			switch signal {
			case syscall.SIGTRAP | 0x80:
				if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
					break
				}
				if newSyscall {
					newSyscall = false
					fmt.Printf("syscall(%d)", regs.Orig_rax)
				} else {
					newSyscall = true
					fmt.Printf(" = %d\n", regs.Rax)
				}
				// TODO: do something with these?
			case syscall.PTRACE_EVENT_VFORK:
			case syscall.PTRACE_EVENT_FORK:
			case syscall.PTRACE_EVENT_CLONE:
			case syscall.PTRACE_EVENT_VFORK_DONE:
			case syscall.PTRACE_EVENT_EXEC:
			case syscall.PTRACE_EVENT_EXIT:
			}
		}
		close(ret)
	}()
	return ret, nil
}
