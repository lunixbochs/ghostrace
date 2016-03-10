package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lunixbochs/ghostrace/ghost"
)

func main() {
	fs := flag.NewFlagSet("ghostrace", flag.ExitOnError)
	follow := fs.Bool("f", false, "follow subprocesses")
	pid := fs.Int("p", -1, "attach to pid")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] -p <pid> | <exe> [args...]\n", os.Args[0])
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])
	args := fs.Args()

	var trace chan *ghost.Event
	var err error
	tracer := ghost.NewTracer()
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
	tracer.ExecFilter(func(c *ghost.Event) (bool, bool) {
		// fmt.Println("exec filter", c)
		// keepParent, followChild
		return true, *follow
	})
	for sc := range trace {
		fmt.Fprintf(os.Stderr, "%+v\n", sc)
	}
}
