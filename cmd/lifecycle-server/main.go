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
	path := flag.String("config", "", "configuration path")
	flag.Parse()
	var c interop.LifecycleConfig
	if e := interop.Load(*path, &c); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if e := interop.LifecycleServer(ctx, c); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
