package main

import (
	"github.com/zukhovich/ssh-tun/cmd/ssh-tun/cli"
)

var (
	Version = "1.0.0" // Set via ldflags at build time.
)

func main() {
	cli.Execute(Version)
}
