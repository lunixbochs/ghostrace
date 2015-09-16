package main

import (
	"fmt"
	"os"
	"strconv"

	"./ghostrace"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./ghostrace <pid>")
		os.Exit(1)
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("Error converting pid: %s\n", err)
		os.Exit(1)
	}
	trace, err := ghostrace.TracePid(pid)
	if err != nil {
		fmt.Printf("Error starting trace: %s\n", err)
		os.Exit(1)
	}
	for sc := range trace {
		fmt.Printf("%+v\n", sc)
	}
}
