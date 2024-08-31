#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

int bpf_main(void* ctx, uint64_t size);

uint32_t ctl_array[2] = { 0, 0 };
uint64_t cntrs_array[2] = { 0, 0 };

void *_bpf_helper_ext_0001(uint64_t map_fd, void *key)
{
	printf("bpf_map_lookup_elem %lu\n", map_fd);
	if (map_fd == 5) {
		return &ctl_array[*(uint32_t *)key];
	} else if (map_fd == 6) {
		return &cntrs_array[*(uint32_t *)key];
	} else {
		return NULL;
	}
	return 0;
}

void* __lddw_helper_map_val(uint64_t val)
{
    printf("map_val %lu\n", val);
    if (val == 5) {
        return (void *)ctl_array;
    } else if (val == 6) {
        return (void *)cntrs_array;
    } else {
        return NULL;
    }
}

uint8_t bpf_mem[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

int main() {
    printf("The value of cntrs_array[0] is %" PRIu64 "\n", cntrs_array[0]);
    printf("calling ebpf program...\n");
    bpf_main(bpf_mem, sizeof(bpf_mem));
    printf("The value of cntrs_array[0] is %" PRIu64 "\n", cntrs_array[0]);
    printf("calling ebpf program...\n");
    bpf_main(bpf_mem, sizeof(bpf_mem));
    printf("The value of cntrs_array[0] is %" PRIu64 "\n", cntrs_array[0]);
    return 0;
}
