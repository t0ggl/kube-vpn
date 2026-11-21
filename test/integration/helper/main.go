package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	mode := flag.String("mode", "echo", "mode: echo, dns, probe, tcp-listen")
	addr := flag.String("addr", ":8080", "listen address")
	controlAddr := flag.String("control", ":8053", "DNS control HTTP address")
	initialIP := flag.String("ip", "172.30.10.20", "initial A record IP for dns mode")
	url := flag.String("url", "", "target URL for probe mode")
	tcpTarget := flag.String("tcp", "", "target host:port for tcp probe")
	timeout := flag.Duration("timeout", 3*time.Second, "probe timeout")
	flag.Parse()

	switch *mode {
	case "echo":
		runEcho(*addr)
	case "tcp-listen":
		runTCPListen(*addr)
	case "dns":
		runDNS(*addr, *controlAddr, *initialIP)
	case "probe":
		runProbe(*url, *tcpTarget, *timeout)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}
}

func runEcho(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "%s\n", host)
	})
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "echo server error: %v\n", err)
		os.Exit(1)
	}
}

func runTCPListen(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tcp listen error: %v\n", err)
		os.Exit(1)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		_, _ = c.Write([]byte("pong\n"))
		_ = c.Close()
	}
}

// runDNS starts a minimal authoritative UDP DNS server that answers any A query
// with the current IP (updatable via HTTP POST /ip?value=x.x.x.x on controlAddr).
func runDNS(dnsAddr, controlAddr, initialIP string) {
	var mu sync.RWMutex
	curIP := net.ParseIP(initialIP).To4()
	if curIP == nil {
		fmt.Fprintf(os.Stderr, "invalid initial IP %q\n", initialIP)
		os.Exit(1)
	}

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				val := strings.TrimSpace(r.URL.Query().Get("value"))
				ip := net.ParseIP(val).To4()
				if ip == nil {
					http.Error(w, "invalid IPv4", http.StatusBadRequest)
					return
				}
				mu.Lock()
				curIP = ip
				mu.Unlock()
			}
			mu.RLock()
			ip := curIP.String()
			mu.RUnlock()
			_, _ = fmt.Fprintf(w, "%s\n", ip)
		})
		_ = http.ListenAndServe(controlAddr, mux)
	}()

	pc, err := net.ListenPacket("udp", dnsAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns listen error: %v\n", err)
		os.Exit(1)
	}
	defer pc.Close()

	buf := make([]byte, 512)
	for {
		n, remote, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			continue
		}
		req := buf[:n]
		// Parse end of QNAME.
		idx := 12
		for idx < n && req[idx] != 0 {
			idx += int(req[idx]) + 1
		}
		if idx+5 > n {
			continue
		}
		qEnd := idx + 5 // null byte + QTYPE(2) + QCLASS(2)
		qType := binary.BigEndian.Uint16(req[idx+1 : idx+3])

		mu.RLock()
		ip4 := append([]byte(nil), curIP...)
		mu.RUnlock()

		// Build response: header + original question + optional A record answer.
		resp := make([]byte, 0, qEnd+16)
		resp = append(resp, req[0], req[1]) // Transaction ID
		resp = append(resp, 0x81, 0x80)     // QR=1, RD=1, RA=1, NOERROR
		resp = append(resp, 0x00, 0x01)     // QDCOUNT=1
		if qType == 1 {                     // A record
			resp = append(resp, 0x00, 0x01) // ANCOUNT=1
		} else {
			resp = append(resp, 0x00, 0x00) // ANCOUNT=0 (e.g. AAAA -> NODATA)
		}
		resp = append(resp, 0x00, 0x00, 0x00, 0x00) // NSCOUNT=0, ARCOUNT=0
		resp = append(resp, req[12:qEnd]...)
		if qType == 1 {
			resp = append(resp,
				0xc0, 0x0c, // Pointer to QNAME at offset 12
				0x00, 0x01, // TYPE A
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x00, 0x01, // TTL 1s
				0x00, 0x04, // RDLENGTH 4
			)
			resp = append(resp, ip4...)
		}
		_, _ = pc.WriteTo(resp, remote)
	}
}

func runProbe(targetURL, tcpTarget string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if tcpTarget != "" {
		d := net.Dialer{Timeout: timeout}
		c, err := d.DialContext(ctx, "tcp", tcpTarget)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcp dial failed: %v\n", err)
			os.Exit(1)
		}
		_ = c.Close()
		fmt.Println("ok")
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad url: %v\n", err)
		os.Exit(1)
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "http get failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "status %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	fmt.Print(string(body))
}
