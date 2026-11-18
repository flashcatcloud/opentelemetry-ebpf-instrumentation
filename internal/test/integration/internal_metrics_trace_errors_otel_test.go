// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const internalMetricsTraceErrorsHostPort = "8398"

// TestInternalOTelMetricsTraceErrors points OBI's OTLP traces endpoint at a
// closed collector port while keeping the metrics endpoint healthy. Every span
// export fails, and with the synchronous-exporter fix (#2716) the instrumented
// exporter observes the failure and records obi.otel.trace.export.errors. That
// counter still rides the healthy metrics endpoint to Prometheus (asserted
// present here) and to weaver for semantic-convention live-check.
// A controlled HTTP rejection also exercises metric export errors, which must
// be exported after recovery rather than depending on startup races.
func TestInternalOTelMetricsTraceErrors(t *testing.T) {
	upstream, err := url.Parse("http://localhost:4318")
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	var rejectMetrics atomic.Bool
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rejectMetrics.Load() {
				// HTTP 400 is a permanent OTLP failure, so SDK retries cannot hide it.
				http.Error(w, "injected metric export failure", http.StatusBadRequest)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { require.NoError(t, server.Close()) })

	compose, err := docker.ComposeSuite("docker-compose-internal-metrics-trace-errors.yml", path.Join(pathOutput, "test-suite-internal-metrics-trace-errors.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+internalMetricsTraceErrorsHostPort+`:8080`,
		fmt.Sprintf("METRICS_ENDPOINT=http://host.docker.internal:%d/v1/metrics", listener.Addr().(*net.TCPAddr).Port),
	)
	require.NoError(t, compose.Up())

	// Cleanups run LIFO: register compose.Close() first so it runs LAST, after
	// runWeaverValidation has /stopped the still-running weaver container.
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	t.Cleanup(func() { runWeaverValidation(t) })

	// Drive continuous HTTP traffic so OBI keeps producing spans it then
	// tries (and fails) to export, incrementing obi.otel.trace.export.errors.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = pokeInternalMetricsTraceErrorsServer()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	defer close(stop)

	t.Run("obi.otel.trace.export.errors exported over OTLP and weaver-validated", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}

		require.Eventually(t, func() bool {
			return pokeInternalMetricsTraceErrorsServer() == nil
		}, testTimeout, 500*time.Millisecond, "testserver never became reachable")

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query("obi_otel_trace_export_errors_total")
			if !assert.NoError(ct, err, "querying obi_otel_trace_export_errors_total") {
				return
			}
			assert.NotEmpty(ct, results, "obi_otel_trace_export_errors_total should be present")
		}, testTimeout, 500*time.Millisecond)
	})

	t.Run("metric export errors survive endpoint recovery", func(t *testing.T) {
		rejectMetrics.Store(true)
		t.Cleanup(func() { rejectMetrics.Store(false) })
		// Cover multiple one-second application metric export intervals.
		time.Sleep(5 * time.Second)
		rejectMetrics.Store(false)

		pq := promtest.Client{HostPort: prometheusHostPort}
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(`obi_otel_metric_export_errors_total{error_type!=""} > 0`)
			if assert.NoError(ct, err) {
				assert.NotEmpty(ct, results, "metric export errors must reach the recovered collector and weaver")
			}
		}, testTimeout, 500*time.Millisecond)
	})
}

func pokeInternalMetricsTraceErrorsServer() error {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:" + internalMetricsTraceErrorsHostPort + "/ping")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
