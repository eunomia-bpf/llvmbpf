#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

int bpf_main(void* ctx, uint64_t size);

unsigned char bpf_mem[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

int main() {
    printf("calling ebpf program...\n");
    int res = bpf_main(bpf_mem, sizeof(bpf_mem));
    printf("return value = %d\n", res);
    return 0;
}