#include <sys/ioctl.h>
#include <unistd.h>
int
main(int argc, char **argv)
{
	ioctl(STDIN_FILENO, TIOCNOTTY);
	return execvp(argv[1], argv + 1);
}
