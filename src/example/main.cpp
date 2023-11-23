#include <cstdio>

#include <uis.h>

int main(int argc, char **argv)
{
	int ret = uis::attach("lo");
	if (ret) {
		return 1;
	}
	ret = uis::attach("lo");
	if (ret) {
		return 1;
	}
	printf("Success: Loading XDP prog\n");
	uis::print_stats();
	printf("Cleanup: Cleanup started\n");

	return 0;
}