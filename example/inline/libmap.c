#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

uint32_t ctl_array[2] = { 0, 0 };
uint64_t cntrs_array[2] = { 0, 0 };

void *_bpf_helper_ext_0001(uint64_t map_fd, void *key)
{
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
    if (val == 5) {
        return (void *)ctl_array;
    } else if (val == 6) {
        return (void *)cntrs_array;
    } else {
        return NULL;
    }
}
