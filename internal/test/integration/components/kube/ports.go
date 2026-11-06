// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube // import "go.opentelemetry.io/obi/internal/test/integration/components/kube"

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

type kindContextKey struct{}

// HostPort returns the loopback endpoint mapped to a container port in this cluster.
func (k *Kind) HostPort(containerPort int) string {
	endpoint, ok := k.hostPorts[containerPort]
	if !ok {
		panic(fmt.Sprintf("kind cluster %s has no host mapping for container port %d", k.clusterName, containerPort))
	}
	return endpoint
}

// HostPort resolves a mapped endpoint for features shared by multiple test suites.
func HostPort(ctx context.Context, containerPort int) string {
	return ctx.Value(kindContextKey{}).(*Kind).HostPort(containerPort)
}

func (k *Kind) discoverHostPorts() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		nodes, err := exec.CommandContext(ctx, "docker", "ps", "-q", "--filter", "label=io.x-k8s.kind.cluster="+k.clusterName).Output()
		if err != nil {
			return ctx, fmt.Errorf("listing kind nodes: %w", err)
		}
		ids := strings.Fields(string(nodes))
		if len(ids) == 0 {
			return ctx, fmt.Errorf("no Docker nodes found for kind cluster %s", k.clusterName)
		}
		output, err := exec.CommandContext(ctx, "docker", append([]string{"inspect"}, ids...)...).Output()
		if err != nil {
			return ctx, fmt.Errorf("inspecting kind port mappings: %w", err)
		}
		k.hostPorts, err = parseHostPorts(output)
		if err != nil {
			return ctx, err
		}
		if !k.promEndpointSet {
			k.promEndpoint = k.hostPorts[9090]
		}
		if !k.jaegerEndpointSet {
			k.jaegerEndpoint = k.hostPorts[16686]
		}
		log().Info("resolved kind host ports", "cluster", k.clusterName, "ports", k.hostPorts)
		return context.WithValue(ctx, kindContextKey{}, k), nil
	}
}

func parseHostPorts(data []byte) (map[int]string, error) {
	var nodes []struct {
		NetworkSettings struct {
			Ports map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string
			}
		}
	}
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, fmt.Errorf("decoding kind port mappings: %w", err)
	}
	ports := map[int]string{}
	for _, node := range nodes {
		for port, bindings := range node.NetworkSettings.Ports {
			if !strings.HasSuffix(port, "/tcp") || len(bindings) == 0 {
				continue
			}
			containerPort, err := strconv.Atoi(strings.TrimSuffix(port, "/tcp"))
			if err != nil {
				return nil, fmt.Errorf("invalid container port %q: %w", port, err)
			}
			if _, exists := ports[containerPort]; exists {
				return nil, fmt.Errorf("container port %d is mapped on multiple kind nodes", containerPort)
			}
			binding := bindings[0]
			host := binding.HostIP
			switch host {
			case "", "0.0.0.0":
				host = "127.0.0.1"
			case "::":
				host = "::1"
			}
			ports[containerPort] = net.JoinHostPort(host, binding.HostPort)
		}
	}
	return ports, nil
}
