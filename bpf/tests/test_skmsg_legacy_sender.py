#!/usr/bin/env python3
"""Exercise the actual compatibility identity predicate, including mismatch rejection."""
from pathlib import Path
import subprocess
import tempfile
source = (Path(__file__).resolve().parents[1] / 'tpinjector/tpinjector.c').read_text()
a = source.index('static __always_inline bool legacy_sender_matches(')
b = source.index('\nstatic __always_inline const conn_pid_t *legacy_sender(', a)
code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
typedef uint64_t u64;
typedef uint32_t u32;
typedef struct { u64 id; struct {u32 host_pid;} p_info; struct {u32 pid, tid;} p_key; } conn_pid_t;
HELPER
int main(void) {
    const u64 id = ((u64)1234 << 32) | 5678;
    conn_pid_t s = {.id=id, .p_info={1234}, .p_key={12,34}};
    assert(legacy_sender_matches(&s,id));
    assert(!legacy_sender_matches(NULL,id));
    assert(!legacy_sender_matches(&s,id+1));
    assert(!legacy_sender_matches(&s,id+((u64)1<<32)));
    s.p_info.host_pid=1235; assert(!legacy_sender_matches(&s,id)); s.p_info.host_pid=1234;
    s.p_key.pid=0; assert(!legacy_sender_matches(&s,id)); s.p_key.pid=12;
    s.p_key.tid=0; assert(!legacy_sender_matches(&s,id)); s.p_key.tid=34;
    assert(legacy_sender_matches(&s,id));
    puts("PASS: exact identity accepted; absent, different thread/process and missing namespace PID/TID rejected");
}
'''.replace('HELPER',source[a:b])
with tempfile.TemporaryDirectory() as tmp:
    c=Path(tmp)/'test.c'; c.write_text(code); binary=Path(tmp)/'test'
    subprocess.run(['clang','-O2','-Wall','-Werror','-fsanitize=address,undefined',str(c),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
