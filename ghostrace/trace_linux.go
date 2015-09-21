package ghostrace

import (
	"fmt"
	"runtime"
	"syscall"
	"time"

	"./memio"
	"./process"
	"./sys"
)

func TraceSpawn(cmd string, args ...string) (chan *Event, error) {
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

func TracePid(pid int) (chan *Event, error) {
	proc, err := process.FindPid(pid)
	if err != nil {
		return nil, err
	}
	return traceProcess(proc, true)
}

func traceProcess(proc process.Process, attach bool) (chan *Event, error) {
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
	options := syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEFORK | syscall.PTRACE_O_TRACEVFORK | syscall.PTRACE_O_TRACESYSGOOD
	if err := syscall.PtraceSetOptions(pid, options); err != nil {
		return nil, err
	}
	var readMem = func(p []byte, addr uint64) (int, error) {
		return syscall.PtracePeekData(pid, uintptr(addr), p)
	}
	var writeMem = func(p []byte, addr uint64) (int, error) {
		return syscall.PtracePokeData(pid, uintptr(addr), p)
	}
	codec, err := sys.NewCodec(sys.ARCH_X86_64, sys.OS_LINUX, memio.NewMemIO(readMem, writeMem))
	if err != nil {
		return nil, err
	}
	ret := make(chan *Event)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		var savedRegs, regs syscall.PtraceRegs
		var stopSig syscall.Signal
		newSyscall := true
	Outer:
		for {
			// wait for syscall entry
			if err := syscall.PtraceSyscall(pid, int(stopSig)); err != nil {
				fmt.Println("DEBUG: " + err.Error())
				break
			}
			if _, err := syscall.Wait4(pid, &status, syscall.WALL, nil); err != nil {
				fmt.Println("DEBUG: " + err.Error())
				break
			}
			if status.Exited() {
				fmt.Println("DEBUG: process exited")
				break
			}
			stopSig = status.StopSignal()
			// are we blocking on a sigstop?
			// TODO: send events upstream for signals
			wasStopped := false
			for stopSig == syscall.SIGSTOP ||
				stopSig == syscall.SIGTTIN || stopSig == syscall.SIGTTOU || stopSig == syscall.SIGTSTP {
				wasStopped = true
				if err := syscall.PtraceCont(pid, int(stopSig)); err != nil {
					fmt.Println("DEBUG: " + err.Error())
					break Outer
				}
				if _, err := syscall.Wait4(pid, &status, syscall.WALL, nil); err != nil {
					fmt.Println("DEBUG: " + err.Error())
					break Outer
				}
				stopSig = status.StopSignal()
				time.Sleep(50 * time.Millisecond)
			}
			// did we get a ptrace event?
			if !wasStopped && (stopSig&syscall.SIGTRAP) != 0 {
				stopSig = syscall.Signal(0)
				switch status.StopSignal() & ^syscall.SIGTRAP {
				case 0x80: // SYSCALL
					if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
						break
					}
					if newSyscall {
						newSyscall = false
						savedRegs = regs
					} else {
						newSyscall = true
						args := []uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8, regs.R9}
						call, err := codec.DecodeRet(int(savedRegs.Orig_rax), args, regs.Rax)
						if err != nil {
							fmt.Println(err)
						} else {
							ret <- &Event{
								Process: proc,
								Syscall: call,
							}
						}
					}
					// TODO: do something with these?
				case syscall.PTRACE_EVENT_VFORK << 8:
				case syscall.PTRACE_EVENT_FORK << 8:
				case syscall.PTRACE_EVENT_CLONE << 8:
				case syscall.PTRACE_EVENT_VFORK_DONE << 8:
				case syscall.PTRACE_EVENT_EXEC << 8:
				case syscall.PTRACE_EVENT_EXIT << 8:
				}
			}
		}
		close(ret)
	}()
	return ret, nil
}
