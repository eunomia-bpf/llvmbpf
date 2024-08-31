int _bpf_helper_ext_0006(const char *fmt, ... );

int bpf_main(void* ctx, int size) {
    _bpf_helper_ext_0006("hello world: %d\n", size);
    return 0;
}
