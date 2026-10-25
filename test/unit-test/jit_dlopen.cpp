#include <dlfcn.h>
#include <cstdio>

int main(int argc, char **argv)
{
	if (argc != 2)
		return 1;
	void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (!module) {
		std::fprintf(stderr, "dlopen: %s\n", dlerror());
		return 2;
	}
	auto run = reinterpret_cast<int (*)()>(dlsym(module, "llvmbpf_test_run"));
	if (!run)
		return 3;
	int result = run();
	if (result != 0)
		std::fprintf(stderr, "JIT/AOT in loaded module failed: %d\n", result);
	if (dlclose(module) != 0)
		return 4;
	return result;
}
