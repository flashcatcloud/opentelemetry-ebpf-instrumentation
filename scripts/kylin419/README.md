# Kylin 4.19 regression

Run this from an amd64 Linux build host with Git, Go and Docker. Set up an SSH
alias for a dedicated Kylin V10 x86_64 guest with a 4.19 kernel, BTF, passwordless
sudo, Bash, curl, flock and Python 3. The guest uses loopback ports 53, 8999 and
18081–18083 and must have port 19999 unused.

Fetch the sync PR before running the regression. Supply its full head SHA, or
the full SHA of a merge candidate that includes the compatibility commits.

```sh
K419_GUEST=obi-kylin419 scripts/kylin419-regression.sh "$commit_sha"
```

Set `K419_REPO` to use a different local Git repository with the commit
available, `K419_SSH_CONFIG` for a separate SSH configuration, `K419_OCI_BIN='sudo -n docker'` when Docker requires sudo, and
`K419_RESULTS_DIR` to change the output directory. The script checks out the
candidate in a temporary clone, generates BPF code and builds the binary and
tests from that commit. The fixtures come from the checkout containing the
runner. Each run saves its commit, guest kernel, build output and guest logs
in a unique results directory. A build or regression failure exits nonzero.

The guest tests cover verifier loading, INET_DIAG fallback across namespaces,
TCP tracepoints and the known sockhash receive behavior. The traffic run
checks split HTTP/1 requests, HTTP/2 remote parents, gRPC, DNS and TCP metrics.
A separate Go run checks concurrent Header injection and preservation. The
sockhash probe is expected to report false EOF on this test kernel and OBI is
expected to disable socket-level injection.
