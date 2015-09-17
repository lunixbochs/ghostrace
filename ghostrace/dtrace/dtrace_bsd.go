package dtrace

import (
	"errors"
	"fmt"
	"unsafe"
)

// #cgo LDFLAGS: -ldtrace
// #include <dtrace.h>
// #include <stdlib.h>
import "C"

type Dtrace struct {
	handle *C.dtrace_hdl_t
}

func dtraceErr(err C.int) error {
	return errors.New(C.GoString(C.dtrace_errmsg(nil, err)))
}

func NewDtrace() (*Dtrace, error) {
	d := &Dtrace{}
	var err C.int
	d.handle = C.dtrace_open(C.DTRACE_VERSION, 0, &err)
	if err != 0 {
		return nil, dtraceErr(err)
	}
	d.SetOpt("bufsize", "4m")
	d.SetOpt("aggsize", "4m")
	return d, nil
}

func (d *Dtrace) err() string {
	return C.GoString(C.dtrace_errmsg(d.handle, C.dtrace_errno(d.handle)))
}

func (d *Dtrace) SetOpt(opt, val string) (err error) {
	optStr, valStr := C.CString(opt), C.CString(val)
	defer C.free(unsafe.Pointer(optStr))
	defer C.free(unsafe.Pointer(valStr))
	if C.dtrace_setopt(d.handle, optStr, valStr) != 0 {
		err = fmt.Errorf("Dtrace.SetOpt() failed: %s", d.err())
	}
	return
}

func (d *Dtrace) GetOpt(opt string) (int64, error) {
	optStr := C.CString(opt)
	defer C.free(unsafe.Pointer(optStr))
	var val C.dtrace_optval_t
	var err error
	if C.dtrace_getopt(d.handle, optStr, &val) != 0 {
		err = fmt.Errorf("Dtrace.GetOpt() failed: %s", d.err())
	}
	return int64(val), err
}

func (d *Dtrace) Compile(source string) error {
	sourceStr := C.CString(source)
	defer C.free(unsafe.Pointer(sourceStr))
	program := C.dtrace_program_strcompile(d.handle, sourceStr, C.DTRACE_PROBESPEC_NAME, 0, 0, nil)
	if program == nil {
		return fmt.Errorf("Dtrace compile failed: %s", d.err())
	}
	var info C.dtrace_proginfo_t
	if C.dtrace_program_exec(d.handle, program, &info) != 0 {
		return fmt.Errorf("Dtrace execute failed: %s", d.err())
	}
	return nil
}

func (d *Dtrace) Version() string {
	return C.GoString(C._dtrace_version)
}
