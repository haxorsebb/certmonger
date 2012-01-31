#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>
int
main(int argc, char **argv)
{
	if (argc < 2) {
		return EINVAL;
	}
	ioctl(STDIN_FILENO, TIOCNOTTY);
	return execvp(argv[1], argv + 1);
}
