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

type execCb func(proc process.Process) bool

type Tracer interface {
	ExecFilter(cb execCb)
	Spawn(cmd string, args ...string) (chan *Event, error)
	Trace(pid int) (chan *Event, error)
}

type LinuxTracer struct {
	execFilter execCb
}

func NewTracer() Tracer {
	return &LinuxTracer{}
}

func (t *LinuxTracer) ExecFilter(cb execCb) {
	t.execFilter = cb
}

func (t *LinuxTracer) Spawn(cmd string, args ...string) (chan *Event, error) {
	pid, err := syscall.ForkExec(cmd, args, &syscall.ProcAttr{
		Sys:   &syscall.SysProcAttr{Ptrace: true},
		Files: []uintptr{0, 1, 2},
	})
	if err != nil {
		return nil, err
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, syscall.WALL, nil); err != nil {
		return nil, err
	}
	return t.traceProcess(pid, false)
}

func (t *LinuxTracer) Trace(pid int) (chan *Event, error) {
	return t.traceProcess(pid, true)
}

func (t *LinuxTracer) traceProcess(pid int, attach bool) (chan *Event, error) {
	if attach {
		if err := syscall.PtraceAttach(pid); err != nil {
			return nil, err
		}
	}
	ret := make(chan *Event)
	proc, err := process.FindPid(pid)
	if err != nil {
		return nil, err
	}
	traced, err := newTracedProc(proc, ret)
	if err != nil {
		return nil, err
	}
	var table = map[int]*tracedProc{pid: traced}
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		defer close(ret)
		for {
			var status syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &status, syscall.WALL, nil)
			if err != nil {
				fmt.Println("DEBUG:", err)
				return
			}
			traced, ok := table[pid]
			if !ok {
				proc, err := process.FindPid(pid)
				if err != nil {
					fmt.Println("DEBUG:", err)
					continue
				}
				if t.execFilter != nil && !t.execFilter(proc) {
					syscall.PtraceDetach(pid)
				} else {
					// TODO: new callback
					t, err := newTracedProc(proc, ret)
					if err != nil {
						fmt.Println("DEBUG:", err)
						continue
					}
					table[pid] = t
				}
			} else {
				if status.Exited() {
					// process exit
				} else {
					if err := traced.Event(status); err != nil {
						fmt.Println("DEBUG:", err)
					}
				}
			}
		}
	}()
	return ret, nil
}

type tracedProc struct {
	Process    process.Process
	Codec      *sys.Codec
	StopSig    syscall.Signal
	NewSyscall bool
	SavedRegs  syscall.PtraceRegs
	Channel    chan *Event
}

func newTracedProc(proc process.Process, ret chan *Event) (*tracedProc, error) {
	pid := proc.Pid()
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
	if err := syscall.PtraceSyscall(pid, 0); err != nil {
		return nil, err
	}
	codec, err := sys.NewCodec(sys.ARCH_X86_64, sys.OS_LINUX, memio.NewMemIO(readMem, writeMem))
	if err != nil {
		return nil, err
	}
	return &tracedProc{
		Process:    proc,
		Codec:      codec,
		NewSyscall: true,
		Channel:    ret,
	}, nil
}

func (t *tracedProc) Event(status syscall.WaitStatus) error {
	pid := t.Process.Pid()
	t.StopSig = status.StopSignal()
	// are we blocking on a sigstop?
	// TODO: send events upstream for signals
	for t.StopSig == syscall.SIGSTOP ||
		t.StopSig == syscall.SIGTTIN || t.StopSig == syscall.SIGTTOU || t.StopSig == syscall.SIGTSTP {
		if err := syscall.PtraceCont(pid, int(t.StopSig)); err != nil {
			return err
		}
		if _, err := syscall.Wait4(pid, &status, syscall.WALL, nil); err != nil {
			return err
		}
		t.StopSig = status.StopSignal()
		time.Sleep(50 * time.Millisecond)
		return nil
	}
	// did we get a ptrace event?
	if t.StopSig&syscall.SIGTRAP != 0 {
		t.StopSig = syscall.Signal(0)
		// SYSCALL
		if status.StopSignal() == syscall.SIGTRAP|0x80 {
			var regs syscall.PtraceRegs
			if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
				return err
			}
			if t.NewSyscall {
				t.NewSyscall = false
				t.SavedRegs = regs
			} else {
				t.NewSyscall = true
				args := []uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8, regs.R9}
				call, err := t.Codec.DecodeRet(int(t.SavedRegs.Orig_rax), args, regs.Rax)
				if err != nil {
					fmt.Println(err)
				} else {
					t.Channel <- &Event{
						Process: t.Process,
						Syscall: call,
					}
				}
			}
		} else {
			switch status.TrapCause() {
			// TODO: send events for these?
			// we don't need to handle them directly
			// because we'll deal with them after getting them back from Wait4()
			case syscall.PTRACE_EVENT_VFORK:
			case syscall.PTRACE_EVENT_FORK:
			case syscall.PTRACE_EVENT_CLONE:
			case syscall.PTRACE_EVENT_VFORK_DONE:
			case syscall.PTRACE_EVENT_EXEC:
			case syscall.PTRACE_EVENT_EXIT:
			default:
				fmt.Println("unknown", status.StopSignal(), status.StopSignal()&^syscall.SIGTRAP)
			}
		}
		if err := syscall.PtraceSyscall(pid, int(t.StopSig)); err != nil {
			return err
		}
	}
	return nil
}
