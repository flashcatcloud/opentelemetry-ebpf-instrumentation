#!/usr/bin/env python3
"""Compile the actual packet-copy helper with guarded pages and exhaustive lengths."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'tpinjector/tpinjector.c').read_text()
start = source.index('static __always_inline u32 copy_msg_window(')
end = source.index('\nstatic __always_inline bool fill_msg_buffers(', start)
helper = source[start:end]
harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
typedef uint32_t u32;
enum { k_msg_buffer_size_max = 8192 };
#define bpf_clamp_umax(value, max) do { if ((value) > (max)) (value) = (max); } while (0)
HELPER
int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    size_t size = ((8193 + page - 1) / page + 1) * page;
    unsigned char *base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(base != MAP_FAILED);
    unsigned char *end = base + size - page;
    assert(mprotect(end, page, PROT_NONE) == 0);
    unsigned char output[8194];
    for (u32 length = 0; length <= 8193; length++) {
        unsigned char *data = end - length;
        for (u32 i = 0; i < length; i++) data[i] = (unsigned char)(i * 17 + 3);
        memset(output, 0xa5, sizeof(output));
        u32 copied = copy_msg_window(output + 1, data, end);
        u32 expected = length < 8192 ? length : 8192;
        assert(copied == expected);
        assert(memcmp(output + 1, data, expected) == 0);
        assert(output[0] == 0xa5);
        for (u32 i = expected + 1; i < sizeof(output); i++) assert(output[i] == 0xa5);
    }
    assert(munmap(base, size) == 0);
    puts("PASS: 8194 lengths, exact contents, guarded source and destination canaries");
}
'''.replace('HELPER', helper)
with tempfile.TemporaryDirectory() as tmp:
    c = Path(tmp) / 'test.c'
    binary = Path(tmp) / 'test'
    c.write_text(harness)
    subprocess.run(['clang', '-O2', '-Wall', '-Werror', '-fsanitize=address,undefined', str(c), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
