package ghostrace

import (
	"fmt"
	"runtime"
	"syscall"

	"./process"
)

func TraceSpawn(cmd string, args ...string) (chan *Syscall, error) {
	pid, err := syscall.ForkExec(cmd, args, &syscall.ProcAttr{
		Sys:   &syscall.SysProcAttr{Ptrace: true},
		Files: []uintptr{0, 1, 2},
	})
	if err != nil {
		return nil, err
	}
	proc, err := process.FindPid(pid)
	if err != nil {
		return nil, err
	}
	return traceProcess(proc, false)
}

func TracePid(pid int) (chan *Syscall, error) {
	proc, err := process.FindPid(pid)
	if err != nil {
		return nil, err
	}
	return traceProcess(proc, true)
}

func traceProcess(proc process.Process, attach bool) (chan *Syscall, error) {
	pid := proc.Pid()
	if attach {
		if err := syscall.PtraceAttach(pid); err != nil {
			return nil, err
		}
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, 0, nil); err != nil {
		return nil, err
	}
	// TODO: set options for following children?
	if err := syscall.PtraceSetOptions(pid, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
		return nil, err
	}
	ret := make(chan *Syscall)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		var savedRegs, regs syscall.PtraceRegs
		newSyscall := true
	Outer:
		for {
			for {
				// wait for syscall entry
				if err := syscall.PtraceSyscall(pid, 0); err != nil {
					fmt.Println("DEBUG: " + err.Error())
					break Outer
				}
				if _, err := syscall.Wait4(pid, &status, 0, nil); err != nil {
					fmt.Println("DEBUG: " + err.Error())
					break Outer
				}
				if status.Exited() {
					fmt.Println("DEBUG: process exited")
					break Outer
				}
				if status.StopSignal() != 0 {
					break
				}
			}
			signal := status.StopSignal()
			switch signal {
			case syscall.SIGTRAP | 0x80:
				if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
					break
				}
				if newSyscall {
					newSyscall = false
					savedRegs = regs
				} else {
					newSyscall = true
					ret <- &Syscall{
						Process: proc,
						Num:     int(savedRegs.Orig_rax),
						Name:    "",
						Args:    []uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8, regs.R9},
						Ret:     regs.Rax,
					}
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
