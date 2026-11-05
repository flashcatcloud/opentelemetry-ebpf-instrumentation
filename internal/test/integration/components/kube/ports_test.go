// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

func TestParseHostPorts(t *testing.T) {
	ports, err := parseHostPorts([]byte(`[
		{"NetworkSettings":{"Ports":{
			"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}],
			"8081/tcp":null,
			"53/udp":[{"HostIp":"0.0.0.0","HostPort":"49153"}]
		}}},
		{"NetworkSettings":{"Ports":{
			"9090/tcp":[{"HostIp":"0.0.0.0","HostPort":"49154"},{"HostIp":"::","HostPort":"49154"}],
			"4320/tcp":[{"HostIp":"::1","HostPort":"49155"}]
		}}}
	]`))
	require.NoError(t, err)
	require.Equal(t, map[int]string{
		8080: "127.0.0.1:49152",
		9090: "127.0.0.1:49154",
		4320: "[::1]:49155",
	}, ports)

	_, err = parseHostPorts([]byte(`not JSON`))
	require.Error(t, err)
	_, err = parseHostPorts([]byte(`[
		{"NetworkSettings":{"Ports":{"9090/tcp":[{"HostPort":"49152"}]}}},
		{"NetworkSettings":{"Ports":{"9090/tcp":[{"HostPort":"49153"}]}}}
	]`))
	require.ErrorContains(t, err, "mapped on multiple kind nodes")
}

func TestDiscoverHostPorts(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = ps ]; then
  echo node1
else
  echo '[{"NetworkSettings":{"Ports":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}],"9090/tcp":[{"HostIp":"127.0.0.1","HostPort":"49153"}],"16686/tcp":[{"HostIp":"127.0.0.1","HostPort":"49154"}]}}}]'
fi
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	k := NewKind("test")
	ctx, err := k.discoverHostPorts()(context.Background(), envconf.New())
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:49152", k.HostPort(8080))
	require.Equal(t, k.HostPort(8080), HostPort(ctx, 8080))
	require.Equal(t, k.HostPort(9090), k.promEndpoint)
	require.Equal(t, k.HostPort(16686), k.jaegerEndpoint)
	require.Panics(t, func() { k.HostPort(8081) })

	overridden := NewKind("other", ExportPrometheus("custom:9090"), ExportJaeger(""))
	_, err = overridden.discoverHostPorts()(context.Background(), envconf.New())
	require.NoError(t, err)
	require.Equal(t, "custom:9090", overridden.promEndpoint)
	require.Empty(t, overridden.jaegerEndpoint)
	require.Equal(t, k.HostPort(8080), HostPort(ctx, 8080))
}

func TestKindSetupFailureCleansUp(t *testing.T) {
	if os.Getenv("OBI_TEST_FAILED_KIND_CREATE") == "1" {
		k := NewKind("failed-create", KindConfig("unused.yml"), WeaverValidation())
		k.Run(&testing.M{})
		return
	}
	dir := t.TempDir()
	script := `#!/bin/sh
echo "$*" >> "$KIND_TEST_COMMANDS"
if [ "$1" = create ]; then
  echo 'failed to bind host port: address already in use' >&2
  exit 1
fi
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kind"), []byte(script), 0o700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	commandsFile := filepath.Join(dir, "commands")
	t.Setenv("KIND_TEST_COMMANDS", commandsFile)
	t.Setenv("OBI_TEST_FAILED_KIND_CREATE", "1")
	cmd := exec.Command(os.Args[0], "-test.run=^TestKindSetupFailureCleansUp$")
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, string(output))
	require.Equal(t, 1, exit.ExitCode(), string(output))
	require.NotContains(t, string(output), "panic:")
	commands, err := os.ReadFile(commandsFile)
	require.NoError(t, err)
	require.Contains(t, string(commands), "create cluster --name failed-create")
	require.Contains(t, string(commands), "delete cluster --name failed-create")
}
