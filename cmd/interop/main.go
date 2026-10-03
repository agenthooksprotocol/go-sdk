package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/agenthooksprotocol/go-sdk/interop"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: interop server|client --config path")
		os.Exit(2)
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	fs.Parse(os.Args[2:])
	var c interop.Config
	if e := interop.Load(*path, &c); e != nil {
		fmt.Fprintln(os.Stderr, "invalid config")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var e error
	if mode == "server" {
		e = interop.Server(ctx, c)
	} else if mode == "client" {
		ctx, done := context.WithTimeout(ctx, 3*time.Minute)
		defer done()
		e = interop.Client(ctx, c)
	} else {
		e = fmt.Errorf("unknown mode")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
