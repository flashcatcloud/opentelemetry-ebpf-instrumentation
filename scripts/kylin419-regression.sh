#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# != 1 || ! ${1:-} =~ ^[0-9a-f]{40}$ || -z ${K419_GUEST:-} ]]; then
    echo "Usage: K419_GUEST=<SSH host alias> $0 <full commit SHA>" >&2
    exit 2
fi
sha=$1
script_dir=$(cd "$(dirname "$0")" && pwd)
repo=${K419_REPO:-"$script_dir/.."}
if [[ $(git -C "$repo" rev-parse --verify "$sha^{commit}") != "$sha" ]]; then
    echo "Fetch commit $sha into $repo before running the regression" >&2
    exit 2
fi

mkdir -p "${K419_RESULTS_DIR:-testoutput/kylin419}"
results=$(mktemp -d "${K419_RESULTS_DIR:-testoutput/kylin419}/$sha.XXXXXXXX")
results=$(cd "$results" && pwd)
work=$(mktemp -d)
guest_dir=
guest_ssh=(ssh -o BatchMode=yes -o ConnectTimeout=10)
if [[ -n ${K419_SSH_CONFIG:-} ]]; then
    guest_ssh+=(-F "$K419_SSH_CONFIG")
fi
guest_ssh+=(-- "$K419_GUEST")
cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n $guest_dir ]]; then
        if "${guest_ssh[@]}" "tar -C '$guest_dir/logs' -cf - ." </dev/null > "$work/logs.tar"; then
            mkdir "$results/guest"
            tar -xf "$work/logs.tar" -C "$results/guest" || status=1
            "${guest_ssh[@]}" "rm -rf -- '$guest_dir'" </dev/null || status=1
        else
            echo "Could not retrieve guest logs from $guest_dir" >&2
            status=1
        fi
    fi
    rm -rf -- "$work"
    if ((status == 0)); then
        echo "PASS $sha"
    else
        echo "FAIL $sha" >&2
    fi
    echo "Logs: $results"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '%s\n' "$sha" > "$results/commit"
"${guest_ssh[@]}" 'set -e; . /etc/os-release; [[ $ID = kylin && $(uname -r) = 4.19.* && $(uname -m) = x86_64 && -r /sys/kernel/btf/vmlinux ]]; sudo -n true; command -v python3 >/dev/null; uname -r' </dev/null | tee "$results/kernel"
echo "Building $sha"
git clone --quiet --shared --no-checkout -- "$repo" "$work/source"
cd "$work/source"
git checkout --quiet --detach "$sha"

export GOOS=linux GOARCH=amd64 CGO_ENABLED=0
make docker-generate BPF_TARGETS=amd64 OCI_BIN="${K419_OCI_BIN:-docker}" > "$results/generate.log" 2>&1
make compile RELEASE_VERSION=kylin419-regression RELEASE_REVISION="$sha" > "$results/build.log" 2>&1

packages=(pkg/obi pkg/ebpf pkg/ebpf/common pkg/internal/netns pkg/internal/ebpf/generictracer
    pkg/internal/ebpf/gotracer pkg/internal/ebpf/tpinjector pkg/internal/statsolly/ebpf pkg/metadata/peer)
go test -count=1 "${packages[@]/#/.\/}" > "$results/unit.log" 2>&1

mkdir "$work/guest"
for package in ebpf/generictracer ebpf/gotracer ebpf/tpinjector statsolly/ebpf; do
    go test -c -tags privileged_tests -o "$work/guest/${package//\//-}.test" "./pkg/internal/$package"
done > "$results/build-tests.log" 2>&1
go build -o "$work/guest/obi-network-fixture" "$script_dir/kylin419/testdata/fixture.go" >> "$results/build-tests.log" 2>&1
cp bin/obi "$work/guest/"
cp "$script_dir"/kylin419/{guest.sh,check.py} "$work/guest/"

guest_dir=$("${guest_ssh[@]}" 'dir=$(mktemp -d /tmp/obi-kylin419.XXXXXXXX) && mkdir "$dir/logs" && printf "%s\n" "$dir"' </dev/null)
if [[ ! $guest_dir =~ ^/tmp/obi-kylin419\.[[:alnum:]]{8}$ ]]; then
    echo "Unexpected guest work directory" >&2
    guest_dir=
    exit 1
fi
tar -C "$work/guest" -cf - . | "${guest_ssh[@]}" "tar -C '$guest_dir' -xf -"
echo "Running on Kylin 4.19"
"${guest_ssh[@]}" "cd '$guest_dir' && bash ./guest.sh" </dev/null | tee "$results/guest-run.log"
