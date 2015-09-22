package main

import (
	"flag"
	"fmt"
	"os"

	"./ghostrace"
	"./ghostrace/sys/call"
)

func main() {
	fs := flag.NewFlagSet("ghostrace", flag.ExitOnError)
	// follow := fs.Bool("f", false, "follow subprocesses")
	pid := fs.Int("p", -1, "attach to pid")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] -p <pid> | <exe> [args...]\n", os.Args[0])
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])
	args := fs.Args()

	var trace chan *ghostrace.Event
	var err error
	tracer := ghostrace.NewTracer()
	if pid != nil && *pid >= 0 {
		trace, err = tracer.Trace(*pid)
	} else {
		if len(args) > 0 {
			trace, err = tracer.Spawn(args[0], args...)
		} else {
			fs.Usage()
			os.Exit(1)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting trace: %s\n", err)
		os.Exit(1)
	}
	tracer.ExecFilter(func(c *call.Execve) (bool, bool) {
		// fmt.Println("exec filter", c)
		return true, true
	})
	for sc := range trace {
		fmt.Fprintf(os.Stderr, "%+v\n", sc)
	}
}
