// derp-guard — a cross-tailnet OAuth admission controller that also supervises
// an unmodified upstream derper as a child process.
//
// It reads a single config file (default /etc/derper/config.toml):
//  1. Loads the on-disk node cache snapshot first (so a Tailscale API outage
//     right after a restart cannot deadlock us with an empty table);
//  2. Concurrently fetches every friend's tailnet device list using read-only
//     OAuth clients (devices:core:read) and builds an in-memory allow table;
//  3. Starts an internal admission HTTP service on 127.0.0.1:<random port>
//     (POST /admit) plus a status endpoint (GET /status) on status_listen;
//  4. Prepares cert directories and CLI arguments for one of the 5 cert/run
//     modes, then spawns and supervises the derper child process, injecting
//     --verify-client-url pointing at the local admission endpoint.
//
// Subcommands:
//
//	derp-guard [serve]  -config /etc/derper/config.toml   run the daemon
//	derp-guard derpmap  -config /etc/derper/config.toml   print an ACL derpMap JSON snippet
//
// File layout:
//
//	main.go       entry point and subcommand dispatch
//	config.go     config parsing and validation
//	guard.go      OAuth sync, three-tier admission, node snapshot persistence
//	supervisor.go derper child process management (backoff restart, graceful restart)
//	cert.go       certificate validation/staging/hashing/fingerprint extraction
//	app.go        admission/status HTTP services, derper args, SIGHUP reload, serve
//	derpmap.go    derpmap subcommand
package main

import (
	"flag"
	"log"
	"os"
	"strings"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	sub := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	if sub != "serve" && sub != "derpmap" {
		log.Fatalf("[MAIN] unknown subcommand %q (available: serve, derpmap)", sub)
	}
	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	configPath := fs.String("config", "/etc/derper/config.toml", "path to config file")
	_ = fs.Parse(args)

	var err error
	switch sub {
	case "serve":
		err = cmdServe(*configPath)
	case "derpmap":
		err = cmdDerpMap(*configPath)
	}
	if err != nil {
		log.Fatalf("[MAIN] FATAL %v", err)
	}
}
