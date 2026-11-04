#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

exec 9>"$HOME/.obi-kylin419.lock"
flock -n 9 || { echo "A Kylin regression is already running" >&2; exit 1; }

run_tests() {
    local binary=$1
    shift
    local pattern
    pattern=$(IFS='|'; echo "$*")
    sudo -n env OBI_TEST_TCP_ITERATOR=1 OBI_TEST_GO_KERNEL_LOAD=1 OBI_TEST_NETWORK=1 \
        OBI_TEST_SOCKHASH_RECEIVE=broken "./$binary.test" -test.v -test.timeout=4m \
        -test.run="^($pattern)$" > "logs/$binary.log" 2>&1
    for name in "$@"; do
        grep -Fq -- "--- PASS: $name (" "logs/$binary.log" ||
            { echo "Required test did not pass: $name" >&2; exit 1; }
    done
}
run_tests ebpf-generictracer TestGenericTracerKernelPrograms TestTCPIteratorFallbackProbeLive \
    TestTCPIteratorFallbackLiveIPv4IPv6 TestTCPIteratorFallbackLiveNetworkNamespace
run_tests ebpf-gotracer TestGoTracerKernelPrograms
run_tests ebpf-tpinjector TestSKMsgCompatibilityPrograms TestSockhashReceiveSemantics
run_tests statsolly-ebpf TestTCPConnectionTracepoints

# The timeout also cleans up privileged processes if the SSH connection drops.
start_privileged() {
    local name=$1
    shift
    sudo -n timeout --kill-after=5s 90s bash -c 'echo "$$" > "$1"; shift; exec "$@"' \
        bash "$name.pid" "$@" > "logs/$name.log" 2>&1 &
    process=$!
}
stop_privileged() {
    local name=$1
    if [[ -s $name.pid ]]; then
        sudo -n kill -TERM "$(cat "$name.pid")" 2>/dev/null || true
        sudo -n rm -f -- "$name.pid"
    fi
}
cleanup() {
    stop_privileged obi
    stop_privileged fixture
    if [[ -n ${client_pid:-} ]]; then
        kill "$client_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_http() {
    local url=$1
    for _ in {1..40}; do
        if curl -fsS --max-time 1 "$url" >/dev/null 2>&1; then
            return
        fi
        sleep 0.25
    done
    echo "Timed out waiting for $url" >&2
    return 1
}

for mode in generic go; do
    echo "Checking $mode traffic"
    skip_go=true
    if [[ $mode == go ]]; then
        skip_go=false
    fi
    cat > obi.yml <<YAML
log_level: debug
trace_printer: json
ebpf:
  track_request_headers: true
  context_propagation: headers
  buffer_sizes:
    http: 262144
    tcp: 65536
metrics:
  features: [application, network, network_flow_packets, stats]
network:
  source: socket_filter
  agent_ip: 127.0.0.1
  exclude_interfaces: []
  interfaces: [lo]
  cache_active_timeout: 1s
stats:
  agent_ip: 127.0.0.1
prometheus_export:
  port: 8999
discovery:
  skip_go_specific_tracers: $skip_go
  services:
    - name: obi-network-fixture
      exe_path: '(^|/)obi-network-fixture$'
YAML
    start_privileged fixture ./obi-network-fixture
    fixture_pid=$process
    wait_http http://127.0.0.1:18081/ready
    if [[ $mode == go ]]; then
        for headers in inject preserve; do
            no_parent=0
            if [[ $headers == inject ]]; then
                no_parent=1
            fi
            OBI_LAB_NO_PARENT=$no_parent OBI_LAB_ROUNDS=48 OBI_LAB_PARALLEL=8 \
                OBI_LAB_CLIENT_WAIT="$PWD/$headers.start" timeout 60s ./obi-network-fixture client \
                > "logs/$headers.log" 2>&1 &
            client_pid=$!
            # The fixture binds the readiness socket before waiting for the marker.
            # In preserve mode the previous client has released the socket.
            sleep 1
            if [[ $headers == inject ]]; then
                start_privileged obi env OBI_LAB_ALLOW_KERNEL_419=1 ./obi -config obi.yml
                obi_pid=$process
                wait_http http://127.0.0.1:8999/metrics
            fi
            sleep 8
            touch "$headers.start"
            wait "$client_pid"
            client_pid=
        done
    else
        start_privileged obi env OBI_LAB_ALLOW_KERNEL_419=1 ./obi -config obi.yml
        obi_pid=$process
        wait_http http://127.0.0.1:8999/metrics
        sleep 6
        timeout 30s ./obi-network-fixture client > logs/generic-client.log 2>&1
        python3 check.py fragment > logs/fragment.log
    fi

    sleep 3
    curl -fsS --max-time 5 http://127.0.0.1:8999/metrics > "logs/$mode.metrics"
    stop_privileged obi
    status=0
    wait "$obi_pid" || status=$?
    if [[ $status != 0 && $status != 143 ]]; then
        echo "OBI exited with status $status during $mode traffic" >&2
        exit 1
    fi
    mv logs/obi.log "logs/$mode.obi.log"
    stop_privileged fixture
    wait "$fixture_pid" || true
    mv logs/fixture.log "logs/$mode.fixture.log"
    python3 check.py "$mode"
done
