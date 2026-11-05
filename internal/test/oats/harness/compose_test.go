// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestComposeBuildRetries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      string
		prebuilt  bool
		compose   string
		wantBuild string
		attempts  int
		wantUp    bool
		wantError bool
	}{
		{name: "truncated layer", mode: "transient", attempts: 2, wantUp: true},
		{name: "retry limit", mode: "persistent", attempts: buildAttempts, wantError: true},
		{name: "compiler error", mode: "compile", attempts: 1, wantError: true},
		{name: "container startup error", mode: "startup", attempts: 1, wantUp: true, wantError: true},
		{name: "prebuilt OBI", prebuilt: true, wantBuild: "build javaagent testserver withargs withtarget", attempts: 1, wantUp: true},
		{name: "all services prebuilt", prebuilt: true, compose: "services:\n  obi:\n    build:\n      dockerfile: " + obiDockerfile + "\n", wantUp: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			script := `#!/bin/sh
if [ "$1" = image ]; then exit 0; fi
while [ "$1" != build ] && [ "$1" != up ]; do shift; done
echo "$*" >> "$DOCKER_TEST_COMMANDS"
if [ "$1" = up ]; then
  [ "$DOCKER_TEST_MODE" != startup ]
  exit $?
fi
count=0
if [ -f "$DOCKER_TEST_COUNT" ]; then read -r count < "$DOCKER_TEST_COUNT"; fi
count=$((count + 1))
echo "$count" > "$DOCKER_TEST_COUNT"
case "$DOCKER_TEST_MODE" in
  transient) [ "$count" -gt 1 ] && exit 0 ;;
  persistent) ;;
  compile) echo 'failed to solve: process go build exited with code 1' >&2; exit 1 ;;
  *) exit 0 ;;
esac
echo 'failed to solve: failed to compute cache key: short read: expected 157573292 bytes but got 23068672: unexpected EOF' >&2
exit 1
`
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("DOCKER_TEST_MODE", tc.mode)
			t.Setenv("DOCKER_TEST_COUNT", filepath.Join(dir, "count"))
			commandsFile := filepath.Join(dir, "commands")
			t.Setenv("DOCKER_TEST_COMMANDS", commandsFile)
			t.Setenv("PREBUILT_IMAGES", "")
			if tc.prebuilt {
				t.Setenv("PREBUILT_IMAGES", prebuiltOBIImage)
			}
			contents := tc.compose
			if contents == "" {
				contents = generatedCompose
			}
			composeFile := filepath.Join(dir, "compose.yml")
			if err := os.WriteFile(composeFile, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := newCompose(composeFile, filepath.Join(dir, "build.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.logger.Close()
			if err := c.up(); (err != nil) != tc.wantError {
				t.Fatalf("up() error = %v, want error = %v", err, tc.wantError)
			}
			commands, err := os.ReadFile(commandsFile)
			if err != nil {
				t.Fatal(err)
			}
			buildCommand := tc.wantBuild
			if buildCommand == "" {
				buildCommand = "build"
			}
			want := strings.Repeat(buildCommand+"\n", tc.attempts)
			if tc.wantUp {
				want += "up --no-build --detach --force-recreate\n"
			}
			if string(commands) != want {
				t.Errorf("commands = %q, want %q", commands, want)
			}
			if tc.mode == "transient" || tc.mode == "persistent" {
				logs, err := os.ReadFile(filepath.Join(dir, "build.log"))
				if err != nil {
					t.Fatal(err)
				}
				failures := tc.attempts
				if !tc.wantError {
					failures--
				}
				if got := bytes.Count(logs, []byte("unexpected EOF")); got != failures {
					t.Errorf("logged failures = %d, want %d", got, failures)
				}
			}
		})
	}
}

const generatedCompose = `
name: oats
services:
  autoinstrumenter:
    build:
      context: /src
      dockerfile: ./internal/test/integration/components/obi/Dockerfile
  absolute:
    build:
      context: /src
      dockerfile: /src/internal/test/integration/components/obi/Dockerfile
  javaagent:
    build:
      context: /src
      dockerfile: ./internal/test/integration/components/obi/Dockerfile-with-javaagent
    image: hatest-obi-javaagent
  withargs:
    build:
      context: /src
      dockerfile: ./internal/test/integration/components/obi/Dockerfile
      args:
        FOO: bar
  withtarget:
    build:
      context: /src
      dockerfile: ./internal/test/integration/components/obi/Dockerfile
      target: builder
  testserver:
    build:
      context: /src
      dockerfile: ./internal/test/integration/components/testserver/Dockerfile
  lgtm:
    image: grafana/otel-lgtm:latest
`

func TestSplitServices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(path, []byte(generatedCompose), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &compose{path: path, files: []string{path}}

	obiServices, toBuild, err := c.splitServices()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"absolute", "autoinstrumenter"}; !slices.Equal(obiServices, want) {
		t.Errorf("obi services = %v, want %v", obiServices, want)
	}
	if want := []string{"javaagent", "testserver", "withargs", "withtarget"}; !slices.Equal(toBuild, want) {
		t.Errorf("services to build = %v, want %v", toBuild, want)
	}
}

func TestSplitServicesRejectsShortFormBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	shortForm := "services:\n  autoinstrumenter:\n    build: ./internal/test/integration/components/obi\n"
	if err := os.WriteFile(path, []byte(shortForm), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &compose{path: path, files: []string{path}}

	if _, _, err := c.splitServices(); err == nil {
		t.Error("expected an error so up() falls back to building every service")
	}
}

func TestUsePrebuiltOBI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	c := &compose{path: path, files: []string{path}}

	if err := c.usePrebuiltOBI([]string{"autoinstrumenter"}); err != nil {
		t.Fatal(err)
	}
	if len(c.files) != 2 {
		t.Fatalf("files = %v, want the generated file plus the override", c.files)
	}
	data, err := os.ReadFile(c.files[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "autoinstrumenter:\n        image: hatest-obi") {
		t.Errorf("override = %q", data)
	}
}
