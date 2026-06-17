package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"review_test/internal/filter"
	"review_test/internal/output"
	"review_test/internal/scan"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("mdnsmap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	cidrRaw := fs.String("cidr", "", "IPv4 CIDR to include, for example 192.168.1.0/24")
	portsRaw := fs.String("ports", "", "ports to include, for example 80,443,5000-5010")
	timeout := fs.Duration("timeout", 5*time.Second, "mDNS response wait timeout")
	format := fs.String("format", "text", "output format: text")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *cidrRaw == "" || *portsRaw == "" {
		fmt.Fprintln(os.Stderr, "error: --cidr and --ports are required")
		fs.Usage()
		return 2
	}
	if *format != "text" {
		fmt.Fprintf(os.Stderr, "error: unsupported format %q\n", *format)
		return 2
	}

	cidr, err := filter.ParseCIDR(*cidrRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid cidr: %v\n", err)
		return 2
	}
	ports, err := filter.ParsePorts(*portsRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid ports: %v\n", err)
		return 2
	}

	scanner := scan.Scanner{Timeout: *timeout}
	assets, err := scanner.Scan(context.Background(), cidr, ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 1
	}

	fmt.Print(output.Text(assets))
	return 0
}
