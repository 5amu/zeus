<h1 align="center"><img width="300px" src="assets/cover.png" alt="Zeus"></h1>
<h4 align="center">fast and reliable local vulnerability scanner</h4>

---

Zeus is used to assess the security of an Operating System using a remote connection. This is achieved by sending commands and checking matching specific rules to the output based on a plugin system.

## Install

You can instal from the release page of this repository, or using `go`:

```
go install -v github.com/5amu/zeus/cmd/zeus@latest
```

## Usage

```
zeus -h
```

This will display the help.

```

Last and reliable local vulnerability scanner over remote connection

Usage:
  ./zeus [flags]

Flags:
TARGET:
   -u, -target string  target host to scan
   -l, -list string    file containing targets to scan

OUTPUT:
   -v, -verbose        set output to verbose
   -o, -output string  set output file

PLUGINS:
   -vp, -validate string    validate specified plugin
   -p, -plugin-path string  path to get plugins from

DEBUG:
   -V, -version      show version and exit
   -t, -threads int  set the number of concurrent hosts to scan (default 4)

```