#!/usr/bin/env python3
"""Exercise the actual sockops state callback's compatibility cleanup policy."""
from pathlib import Path
import subprocess,tempfile
s=(Path(__file__).resolve().parents[1]/'tpinjector/tpinjector.c').read_text()
a=s.index('static __always_inline void bpf_sock_ops_state_cb(')
b=s.index('\nstatic __always_inline void bpf_sock_ops_passive_est_cb(',a)
code=r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#define __always_inline inline __attribute__((always_inline))
typedef uint32_t u32; typedef uint64_t u64;
enum { BPF_TCP_CLOSE=7, BPF_TCP_CLOSE_WAIT=8 };
struct bpf_sock_ops { u32 args[4]; };
static bool legacy_sk_msg;
static int sock_dir,tracked_sock_cookies,detached,untracked;
static u64 bpf_get_socket_cookie(struct bpf_sock_ops *s) {return 123;}
static int bpf_map_delete_elem(void *map,const u64 *key) {
 assert(*key==123); if(map==&sock_dir)detached++;else {assert(map==&tracked_sock_cookies);untracked++;} return 0;
}
HELPER
int main(void) {
 for(int legacy=0;legacy<2;legacy++)for(int state=1;state<=12;state++) {
  legacy_sk_msg=legacy;detached=untracked=0;
  struct bpf_sock_ops s={.args={1,state}};bpf_sock_ops_state_cb(&s);
  assert(detached==(legacy && state==BPF_TCP_CLOSE_WAIT));
  assert(untracked==(state==BPF_TCP_CLOSE || (legacy && state==BPF_TCP_CLOSE_WAIT)));
 }
 puts("PASS: legacy FIN detach; established/other states preserved; modern path unchanged; close cleanup preserved");
}
'''.replace('HELPER',s[a:b])
with tempfile.TemporaryDirectory() as t:
 p=Path(t);(p/'test.c').write_text(code)
 subprocess.run(['clang','-O2','-Wall','-Werror','-Wno-macro-redefined','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
