/*
 * fat_fuse.c
 *
 * main() for a program to mount a FAT filesystem using FUSE
 */

#include <alloca.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "fat_volume.h"
#include "fat_fuse_ops.h"
#include "fat_util.h"

static void
usage()
{
	const char *usage_str =
"Usage: fat-fuse [-o option[,...]] VOLUME MOUNTPOINT\n";
	fputs(usage_str, stdout);
}

static void
usage_short()
{
	const char *usage_str =
"Usage: fat-fuse [-o option[,...]] VOLUME MOUNTPOINT\n";
	fputs(usage_str, stderr);
}

static const char *shortopts = "o:h";
static const struct option longopts[] = {
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};


enum mount_option_type {
	MOUNT_OPTION_PRIVATE,
	MOUNT_OPTION_SHARED,
	MOUNT_OPTION_UNKNOWN,
};

static enum mount_option_type
process_mount_option(char *option, int *mount_flags_p)
{
	if (!strcmp(option, "ro")) {
		*mount_flags_p &= ~FAT_MOUNT_FLAG_READWRITE;
		return MOUNT_OPTION_SHARED;
	}
	return MOUNT_OPTION_UNKNOWN;
}

static char *
inline_stpcpy(char *dst, const char *src)
{
	while ((*dst = *src))
		src++, dst++;
	return dst;
}

/* Parse the comma-separated string of mount options provided by the user.
 * There are 3 types of options (not all are actually used yet):
 *
 * MOUNT_OPTION_PRIVATE:  An option understood only by this specific filesystem
 *                        implementation that will not be passed to fuse_main().
 *
 * MOUNT_OPTION_SHARED:   An option understood by this filesystem, but also
 *                        passed to fuse_main().
 *
 * MOUNT_OPTION_UNKNOWN:  An option that this filesystem does not understand
 *                        and is passed directly to fuse_main().
 *
 * The return value here is the option string to pass to fuse_main().
 * *mount_flags_p is modified to change the way in which this specific
 * filesystem will be mounted.
 */
static char *
parse_mount_options(char *optstring, int *mount_flags_p)
{
	char *new_opts_end;
	char *tok_start, *tok_end;
	enum mount_option_type opttype;

	new_opts_end = optstring;
	tok_start = optstring;
	for (;;) {
		tok_end = strchr(tok_start, ',');
		if (tok_end)
			*tok_end = '\0';
		opttype = process_mount_option(tok_start, mount_flags_p);
		if (opttype != MOUNT_OPTION_PRIVATE) {
			if (new_opts_end != optstring)
				*new_opts_end++ = ',';
			new_opts_end = inline_stpcpy(new_opts_end, tok_start);
		}
		if (!tok_end)
			break;
		tok_start = tok_end + 1;
	}
	return optstring;
}

int
main(int argc, char **argv)
{
	char *volume;
	char *mountpoint;
	char *optstring = NULL;
	int c;
	struct fat_volume *vol;
	char *fuse_argv[20];
	int fuse_argc;
	int fuse_status;
	int ret;
	int mount_flags;

	while ((c = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1)
	{
		switch (c) {
		case 'h':
			usage();
			return 0;
		case 'o':
			optstring = optarg;
			break;
		default:
			usage_short();
			return 2;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc != 2) {
		usage_short();
		return 2;
	}

	volume = argv[0];
	mountpoint = argv[1];
	mount_flags = FAT_MOUNT_FLAG_READWRITE;
	if (optstring)
		optstring = parse_mount_options(optstring, &mount_flags);
	if (mount_flags & FAT_MOUNT_FLAG_READWRITE) {
		fat_error("Warning: read-write mount not supported yet; assuming -o ro");
		mount_flags &= ~FAT_MOUNT_FLAG_READWRITE;
		if (optstring) {
			char *fixed_optstring;

			fixed_optstring = alloca(strlen(optstring) + sizeof(",ro"));
			sprintf(fixed_optstring, "%s,ro", optstring);
			optstring = fixed_optstring;
		} else {
			optstring = "ro";
		}
	}

	/* Mount the FAT volume with the necessary mount flags */
	vol = fat_mount(volume, mount_flags);
	if (!vol) {
		fat_error("Failed to mount FAT volume \"%s\": %m",
			  volume);
		return 1;
	}
	fuse_argc = 0;
	fuse_argv[fuse_argc++] = "fat-fuse";
	if (optstring) {
		fuse_argv[fuse_argc++] = "-o";
		fuse_argv[fuse_argc++] = optstring;
		DEBUG("Using FUSE optstring \"%s\"", optstring);
	}
	fuse_argv[fuse_argc++] = "-s"; /* Single-threaded */
	fuse_argv[fuse_argc++] = mountpoint;
	fuse_argv[fuse_argc] = NULL;

	/* Call fuse_main() to pass control to FUSE.  This will daemonize the
	 * process, causing it to detach from the terminal.  fat_unmount() will
	 * not be called until the filesystem is unmounted and fuse_main()
	 * returns in the daemon process. */
	fuse_status = fuse_main(fuse_argc, fuse_argv, &fat_fuse_operations, vol);
	ret = fat_unmount(vol);
	if (ret)
		fat_error("failed to unmount FAT volume \"%s\": %m", volume);
	else
		ret = fuse_status;
	return ret;
}
