#include "fat_util.h"
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* Like pread(), but keep trying until everything has been read or we know for
 * sure that there was an error (or end-of-file) */
size_t
full_pread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t bytes_read;
	size_t bytes_remaining;

	for (bytes_remaining = count;
	     bytes_remaining != 0;
	     bytes_remaining -= bytes_read, buf += bytes_read,
	     	offset += bytes_read)
	{
		bytes_read = pread(fd, buf, bytes_remaining, offset);
		if (bytes_read <= 0) {
			if (bytes_read == 0)
				errno = EIO;
			else if (errno == EINTR)
				continue;
			break;
		}
	}
	return count - bytes_remaining;
}

/* Print an error message. */
void
fat_error(const char *format, ...)
{
	va_list va;

	fputs("fat-fuse: ", stderr);
	va_start(va, format);
	vfprintf(stderr, format, va);
	putc('\n', stderr);
	va_end(va);
}

/* Strip trailing spaces from a string */
void
remove_trailing_spaces(char *s)
{
	char *p = strchr(s, '\0');
	while (--p >= s && *p == ' ')
		*p = '\0';
}
