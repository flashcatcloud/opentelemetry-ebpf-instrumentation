// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	pb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "client" {
		client()
		return
	}
	go func() {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:53")
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		b := make([]byte, 4096)
		for {
			n, a, e := conn.ReadFrom(b)
			if e != nil {
				return
			}
			if n < 12 {
				continue
			}
			end := 12
			for end < n && b[end] != 0 {
				end += int(b[end]) + 1
			}
			end += 5
			if end > n {
				continue
			}
			resp := append([]byte{}, b[:end]...)
			resp[2] = 0x81
			resp[3] = 0x80
			resp[6] = 0
			resp[7] = 0
			resp[10] = 0
			resp[11] = 0
			if b[end-3] == 1 {
				resp[7] = 1
				resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
			}
			conn.WriteTo(resp, a)
		}
	}()
	go func() {
		l, e := net.Listen("tcp", "127.0.0.1:18082")
		if e != nil {
			log.Fatal(e)
		}
		s := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			values := md.Get("traceparent")
			grpc.SetHeader(ctx, metadata.Pairs("seen-traceparent", strings.Join(values, ","), "seen-traceparent-count", strconv.Itoa(len(values))))
			return next(ctx, req)
		}))
		h := health.NewServer()
		h.SetServingStatus("", pb.HealthCheckResponse_SERVING)
		pb.RegisterHealthServer(s, h)
		log.Fatal(s.Serve(l))
	}()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, e := io.Copy(io.Discard, r.Body)
		if e != nil {
			log.Print(e)
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s %s body=%d traceparent=%s traceparent_count=%d\n", r.Proto, r.URL.Path, n, r.Header.Get("traceparent"), len(r.Header.Values("traceparent")))
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:18081", h2c.NewHandler(handler, &http2.Server{})))
}
func client() {
	if os.Getenv("OBI_LAB_CLIENT_WAIT") != "" {
		ready, e := net.Listen("tcp4", "127.0.0.1:18083")
		if e != nil {
			log.Fatal(e)
		}
		defer ready.Close()
		for {
			if _, e := os.Stat(os.Getenv("OBI_LAB_CLIENT_WAIT")); e == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	h1 := &http.Client{Timeout: 5 * time.Second}
	h2 := &http.Client{Timeout: 5 * time.Second, Transport: &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, n, a string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}}}
	conn, e := grpc.NewClient("127.0.0.1:18082", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if e != nil {
		log.Fatal(e)
	}
	defer conn.Close()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", "127.0.0.1:53")
	}}
	if refused, err := net.DialTimeout("tcp", "127.0.0.1:19999", time.Second); err == nil {
		refused.Close()
		log.Fatal("expected a refused TCP connection")
	}
	round := func(i int) {
		for j, c := range []*http.Client{h1, h2} {
			for _, size := range []int{0, 80 * 1024} {
				path := fmt.Sprintf("/probe/h%d/size%d/%d", j+1, size, i)
				req, _ := http.NewRequest("POST", "http://127.0.0.1:18081"+path, bytes.NewReader(bytes.Repeat([]byte("x"), size)))
				req.Header.Set("Content-Type", "application/octet-stream")
				if os.Getenv("OBI_LAB_NO_PARENT") != "1" {
					req.Header.Set("Traceparent", "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01")
				}
				resp, e := c.Do(req)
				if e != nil {
					log.Fatal(e)
				}
				b, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != http.StatusOK {
					log.Fatalf("response %s: status %d, read error %v", path, resp.StatusCode, err)
				}
				fmt.Print(string(b))
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if os.Getenv("OBI_LAB_NO_PARENT") != "1" {
			ctx = metadata.AppendToOutgoingContext(ctx, "traceparent", "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01")
		}
		var incoming metadata.MD
		r, e := pb.NewHealthClient(conn).Check(ctx, &pb.HealthCheckRequest{}, grpc.Header(&incoming))
		cancel()
		if e != nil {
			log.Fatal(e)
		}
		fmt.Printf("grpc %s traceparent=%s traceparent_count=%s\n", r.Status, strings.Join(incoming.Get("seen-traceparent"), ","), strings.Join(incoming.Get("seen-traceparent-count"), ","))
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		a, e := resolver.LookupHost(ctx, fmt.Sprintf("probe%d.test", i))
		cancel()
		if e != nil || len(a) != 1 || a[0] != "127.0.0.1" {
			log.Fatalf("DNS lookup returned %v: %v", a, e)
		}
		time.Sleep(500 * time.Millisecond)
	}
	rounds, err := strconv.Atoi(os.Getenv("OBI_LAB_ROUNDS"))
	if err != nil || rounds < 1 {
		rounds = 12
	}
	parallel, err := strconv.Atoi(os.Getenv("OBI_LAB_PARALLEL"))
	if err != nil || parallel < 1 {
		parallel = 1
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	for i := range rounds {
		sem <- struct{}{}
		wg.Go(func() { defer func() { <-sem }(); round(i) })
	}
	wg.Wait()
}
