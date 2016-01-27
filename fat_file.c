/*
 * fat_file.c
 *
 * Operate on FAT files and directories.
 */

#include <alloca.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "fat_file.h"
#include "fat_util.h"
#include "fat_volume.h"

/* Format of a FAT directory entry on disk (32 bytes) */
struct fat_dir_entry_disk {
	u8 base_name[8];
	u8 extension[3];
	u8 attribs;
	u8 reserved;
	u8 create_time_fine_res;
	le16 create_time;
	le16 create_date;
	le16 last_access_date;
	union {
		le16 file_access_bitmap;
		le16 fat32_start_cluster_high;
	};
	le16 last_modified_time;
	le16 last_modified_date;
	le16 start_cluster;
	le32 file_size;
} __attribute__((packed));

/* FAT names can be no more than 12 characters long, so we might as well just
 * inline strcmp() to make comparisons faster. */
static inline int
inline_strcmp(const char *s1, const char *s2)
{
	while (*s1 && *s1 == *s2)
		s1++, s2++;
	return *s1 - *s2;
}

static int
_avl_cmp_fat_files(const struct avl_tree_node *node1,
		   const struct avl_tree_node *node2)
{
	return inline_strcmp(FAT_FILE(node1)->dentry.name,
			     FAT_FILE(node2)->dentry.name);
}

static int
_avl_cmp_name_to_fat_file(const void *name,
			  const struct avl_tree_node *node)
{
	return inline_strcmp((const char *)name, FAT_FILE(node)->dentry.name);
}

/* Flag indicating that the character is legal to use in a filename */
#define FAT_CHAR_LEGAL_IN_FILENAME 0x1

/* Table of 1-byte characters and their interpretations in the FAT filesystem.
 * */
static const unsigned char _fat_char_tab[256] = {
	['a' ... 'z'] = FAT_CHAR_LEGAL_IN_FILENAME,
	['A' ... 'Z'] = FAT_CHAR_LEGAL_IN_FILENAME,
	['0' ... '9'] = FAT_CHAR_LEGAL_IN_FILENAME,
	[128 ... 255] = FAT_CHAR_LEGAL_IN_FILENAME,
	[' ']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['$']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['%']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['-']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['_']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['@']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['~']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['`']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['!']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['(']         = FAT_CHAR_LEGAL_IN_FILENAME,
	[')']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['{']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['}']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['^']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['#']         = FAT_CHAR_LEGAL_IN_FILENAME,
	['&']         = FAT_CHAR_LEGAL_IN_FILENAME,
};

/* Returns %true iff the given character is legal in a FAT filename */
static bool
fat_char_legal_in_filename(char c)
{
	return (_fat_char_tab[(unsigned char)c] & FAT_CHAR_LEGAL_IN_FILENAME) != 0;
}

/* Returns %true iff the given FAT base filename of up to 8 bytes is valid. */
static bool
fat_base_name_valid(const u8 base_name[8])
{
	unsigned i;
	if (base_name[0] == '\0' || base_name[0] == ' ' ||
	    base_name[0] == 0xe5)
	{
		/* End of directory, or name starts with space, or free
		 * directory entry */
		return false;
	}

	/* Make sure all remaining characters are legal */
	i = 0;
	do {
		if (!fat_char_legal_in_filename(base_name[i]))
			return false;
		i++;
	} while (i != 8 && base_name[i] != '\0' && base_name[i] != ' ');
	return true;
}

/* Returns %true if the given FAT filenamne extension of up to 3 bytes is valid.
 * */
static bool
fat_extension_valid(const u8 extension[3])
{
	unsigned i;
	for (i = 0; i < 3 && extension[i] != '\0' && extension[i] != ' '; i++)
		if (!fat_char_legal_in_filename(extension[i]))
			return false;
	return true;
}

/* Returns %true iff the given FAT on-disk directory entry is the special
 * end-of-directory entry. */
static bool
fat_is_end_of_directory(const struct fat_dir_entry_disk *disk_dentry)
{
	return disk_dentry->base_name[0] == '\0';
}

/* Returns %true iff the filesystem driver should ignore the given directory
 * entry due to having invalid attributes or an invalid name. */
static bool
fat_ignore_dentry(const struct fat_dir_entry_disk *disk_dentry)
{
	/* Note: VFAT entries have FILE_ATTRIBUTE_VOLUME set, so they will be
	 * correctly ignored by this long-name unaware code. */
	return (disk_dentry->attribs & (FILE_ATTRIBUTE_VOLUME)) ||
		!fat_base_name_valid(disk_dentry->base_name) ||
		!fat_extension_valid(disk_dentry->extension);
}

/* Add a new directory entry to a directory (in-memory only).
 *
 * Return %true if inserted; %false if duplicate entry. */
static bool
fat_insert_child(struct fat_file *dir, struct fat_file *child)
{

	return !avl_tree_insert(&dir->dir.children, &child->sibling_node,
				_avl_cmp_fat_files);
}

/* Return the actual length of a FAT base name or extension that may be up to
 * @max_len bytes long.  Treats space and null character as ending the name. */
static unsigned
fat_name_len(const u8 *name, unsigned max_len)
{
	unsigned len = max_len;
	do {
		if (name[len - 1] != ' ' && name[len - 1] != '\0')
			break;
	} while (--len);
	return len;
}

/* Initialize an in-memory FAT directory entry from a FAT directory entry in the
 * on-disk format. */
static void
init_fat_dir_entry(struct fat_dir_entry *dentry,
		   const struct fat_dir_entry_disk *disk_dentry,
		   bool is_fat32)
{
	unsigned name_len;
	unsigned extension_len;
	char *dst_name_p;
	const u8 *src_name_p;

	/* Get the base name of the file or directory */
	dst_name_p = dentry->name;
	src_name_p = disk_dentry->base_name;
	name_len = fat_name_len(src_name_p, 8);
	/* Base name cannot be 0 length (it would have been marked as invalid
	 * otherwise) */
	do {
		*dst_name_p++ = *src_name_p++;
	} while (--name_len);

	/* Append extension, if present, to the base name */
	extension_len = fat_name_len(disk_dentry->extension, 3);
	if (extension_len) {
		*dst_name_p++ = '.';
		src_name_p = disk_dentry->extension;
		do {
			*dst_name_p++ = *src_name_p++;
		} while (--extension_len);
	}
	*dst_name_p = '\0';

	/* Get other information, including attributes, timestamps, start
	 * cluster of file data, and file size */
	dentry->attribs = disk_dentry->attribs;
	dentry->create_time = le16_to_cpu(disk_dentry->create_time);
	dentry->create_date = le16_to_cpu(disk_dentry->create_date);
	dentry->last_access_date = le16_to_cpu(disk_dentry->last_access_date);
	dentry->last_modified_time = le16_to_cpu(disk_dentry->last_modified_time);
	dentry->last_modified_date = le16_to_cpu(disk_dentry->last_modified_date);

	dentry->start_cluster = le16_to_cpu(disk_dentry->start_cluster);
	if (is_fat32) {
		/* FAT32 uses a 32-bit start cluster field, but it's split into
		 * two different 16-bit locations on disk. */
		dentry->start_cluster |=
			(u32)le16_to_cpu(disk_dentry->fat32_start_cluster_high) << 16;
	}
	dentry->file_size = le32_to_cpu(disk_dentry->file_size);
}

/* Try to free some `struct fat_file's that haven't been used in a while. */
static void
fat_vol_free_old_files(struct fat_volume *vol)
{
	while (vol->num_allocated_files > vol->max_allocated_files &&
	       !list_empty(&vol->lru_file_list))
	{
		struct fat_file *file;

		file = list_entry(vol->lru_file_list.prev, struct fat_file,
				  lru_list);
		fat_destroy_file_tree(file);
	}
}

/* Read all the child dentries of a FAT directory into memory. */
int
fat_dir_read_children(struct fat_file *dir)
{
	u32 chunk_size;
	off_t cur_offset;
	u32 cur_cluster;
	struct fat_volume *vol;
	u8 *buf;
	const struct fat_dir_entry_disk *disk_dentry_ptr;
	struct fat_file *child;
	u32 dir_entries_processed;

	if (!(dir->dentry.attribs & FILE_ATTRIBUTE_DIRECTORY)) {
		errno = ENOTDIR;
		return -1;
	}
	DEBUG("Reading children of \"%s\"", dir->dentry.name);
	vol = dir->volume;
	dir->dir.children = NULL;
	if (!fat_file_is_root(dir) || vol->type == FAT_TYPE_FAT32) {
		chunk_size = 1 << vol->cluster_order;
		cur_cluster = dir->dentry.start_cluster;
		if (!fat_is_valid_cluster_number(vol, cur_cluster)) {
			DEBUG("cluster number %u is invaled", cur_cluster);
			errno = EIO;
			return -1;
		}
		cur_offset = fat_data_cluster_offset(vol, cur_cluster);
	} else {
		/* Special case:  Root directory entries on FAT12 and FAT16 are
		 * stored in a fixed location, not in the data area. */
		chunk_size = vol->bytes_per_sector;
		cur_offset = (off_t)(vol->num_tables * vol->sectors_per_fat +
				     vol->reserved_sectors) << vol->sector_order;
		cur_cluster = FAT_CLUSTER_END_OF_CHAIN;
	}

	buf = alloca(chunk_size);
	dir_entries_processed = 0;
	for (;;) {
		const struct fat_dir_entry_disk *end_ptr;

		DEBUG("Read %u bytes at offset %"PRIu64" (cluster %u)",
		      chunk_size, cur_offset, cur_cluster);

		end_ptr = (const struct fat_dir_entry_disk*)(buf + chunk_size) - 1;
		if (full_pread(vol->fd, buf, chunk_size,
			       cur_offset) != chunk_size)
			goto err_destroy_tree;
		for (disk_dentry_ptr = (const struct fat_dir_entry_disk*)buf;
		     disk_dentry_ptr <= end_ptr;
		     disk_dentry_ptr++, dir_entries_processed++)
		{
			if (fat_is_end_of_directory(disk_dentry_ptr))
				goto out_success;
			if (fat_ignore_dentry(disk_dentry_ptr))
				continue;
			child = calloc(1, sizeof(*child));
			if (!child)
				goto err_destroy_tree;
			vol->num_allocated_files++;
			fat_vol_free_old_files(vol);
			init_fat_dir_entry(&child->dentry, disk_dentry_ptr,
					   vol->type == FAT_TYPE_FAT32);
			fat_file_init(child, vol);
			child->parent = dir;
			if (!fat_insert_child(dir, child)) {
				/* Duplicate entry */
				free(child);
				vol->num_allocated_files--;
			}
		}
		if (cur_cluster == FAT_CLUSTER_END_OF_CHAIN) {
			/* Reading root directory on non-FAT32 */
			if (dir_entries_processed >= vol->max_root_entries)
				goto out_success;
			cur_offset += chunk_size;
		} else {
			cur_cluster = fat_next_cluster(vol, cur_cluster);
			if (cur_cluster == FAT_CLUSTER_END_OF_CHAIN)
				goto out_success;
			cur_offset = fat_data_cluster_offset(vol, cur_cluster);
		}
	}
out_success:
	dir->children_read = 1;
	return 0;
err_destroy_tree:
	fat_destroy_file_tree(dir);
	return -1;
}


/* Look up a child of a FAT directory, reading the children into memory if
 * needed.  Return NULL and set errno to ENOTDIR if the FAT file is not actually
 * a directory.  Otherwise returns NULL and sets ENOENT if the file is not
 * found, or a pointer to the located file otherwise. */
static struct fat_file *
fat_dir_lookup(struct fat_file *dir, const char *name)
{
	struct avl_tree_node *node;

	if (!dir->children_read)
		if (fat_dir_read_children(dir))
			return NULL;

	node = avl_tree_lookup(dir->dir.children, name, _avl_cmp_name_to_fat_file);
	if (!node) {
		errno = ENOENT;
		return NULL;
	}

	return FAT_FILE(node);
}

static void
fat_file_touch(struct fat_file *file)
{
	/* If a file is no longer opened and has no decendents that are opened,
	 * and is a directory that has children that have been read into memory,
	 * those children are candidates for being freed, so we should push this
	 * file onto the LRU list. */
	if (file->subdir_num_times_opened == 0 && file->children_read)
		list_move(&file->lru_list, &file->volume->lru_file_list);
}

/* Retrieve the `struct fat_file' for a given absolute path on the FAT volume.
 * If not found or another error occurs, returns NULL and sets errno. */
struct fat_file *
fat_pathname_to_file(struct fat_volume *vol, const char *path)
{
	struct fat_file *cur, *file;
	const char *name_begin, *name_end;
	char save;

	cur = &vol->root;
	for (;;) {
		/* We do not want the LRU code to free any of the ancestors of
		 * the node we are trying to look up.  So delete them from the
		 * LRU list (if they are in it), and add them back later. */
		list_del_init(&cur->lru_list);

		/* Get the next path component */
		while (*path == '/')
			path++;
		if (*path == '\0') /* Path is finished.  We got the file we wanted. */
			break;
		name_begin = path;
		name_end = name_begin;
		do {
			name_end++;
		} while (*name_end != '/' && *name_end != '\0');
		save = *name_end;
		*(char*)name_end = '\0';

		/* Look up the path component in the current directory */
		cur = fat_dir_lookup(cur, name_begin);
		*(char*)name_end = save;
		if (!cur) /* Not found */
			break;
		/* Continue to the next path component */
		path = name_end;
	}
	for (file = cur; file != NULL; file = file->parent)
		fat_file_touch(file);
	return cur;
}

static void
fat_file_free(struct fat_file *file)
{
	if (fat_file_is_directory(file))
		fat_destroy_file_tree(file);
	else
		fat_file_free_cluster_cache(file);
	free(file);
}

/* Free child `struct fat_files' (if any) of a `struct fat_file' */
void
fat_destroy_file_tree(struct fat_file *root)
{
	struct fat_file *child;
	if (root->children_read) {
		DEBUG("Destroying file tree rooted at \"%s\"", root->dentry.name);
		fat_dir_for_each_child_safe(child, root) {
			fat_file_free(child);
			root->volume->num_allocated_files--;
		}
		list_del_init(&root->lru_list);
		root->children_read = 0;
	}
}

/* Allocate the table of clusters for a FAT file. */
int
fat_file_alloc_cluster_cache(struct fat_file *file)
{
	u32 cluster_order;
	u32 num_clusters;
	u32 i;

	cluster_order = file->volume->cluster_order;
	num_clusters = ((off_t)file->dentry.file_size +
			((1 << cluster_order) - 1)) >> cluster_order;

	if (num_clusters == 0) /* Zero-length file */
		return 0;

	file->file.cluster_cache = malloc(num_clusters *
					  sizeof(file->file.cluster_cache[0]));
	file->file.num_clusters = num_clusters;
	if (!file->file.cluster_cache)
		return -1;

	/* We don't read the whole table right away: we just read the first
	 * entry, then read the rest on demand. */
	file->file.cluster_cache[0] = file->dentry.start_cluster;
	for (i = 1; i < num_clusters; i++)
		file->file.cluster_cache[i] = FAT_CLUSTER_END_OF_CHAIN;
	file->file.last_known_cluster_idx = 0;
	return 0;
}

/* Free the table of clusters for a FAT file */
void
fat_file_free_cluster_cache(struct fat_file *file)
{
	if (file->file.cluster_cache) {
		free(file->file.cluster_cache);
		file->file.cluster_cache = NULL;
	}
}

/* Increment the number of times that a FAT file or directory has been opened */
void
fat_file_inc_num_times_opened(struct fat_file *file)
{
	file->num_times_opened++;
	do {
		file->subdir_num_times_opened++;

		/* Maybe delete from LRU list */
		list_del_init(&file->lru_list);
	} while ((file = file->parent));
}

/* Decrement the number of times that a FAT file or directory has been opened */
void
fat_file_dec_num_times_opened(struct fat_file *file)
{
	file->num_times_opened--;
	do {
		--file->subdir_num_times_opened;
		fat_file_touch(file);
	} while ((file = file->parent));
}

/* Given a 16-bit FAT date and 16-bit FAT time in the eccentric FAT format,
 * return a standard UNIX time (seconds since January 1, 1970). */
static time_t
fat_time_to_unix_time(u16 date, u16 time)
{
	/* FAT dates are years since 1980.  mktime() expects years since 1900.
	 * */
	u16 year = (date >> 9) + (1980 - 1900);

	/* FAT months are numbered 1-12; mktime() expects months numbered 0-11.
	 * */
	u16 month = ((date >> 5) & 0xf) - 1;

	/* Both FAT days and mktime() mdays are numbered 1-31. */
	u16 day = date & 0x1f;

	/* Hours (0-23) */
	u16 hours = time >> 11;

	/* Minutes (0-59) */
	u16 minutes = (time >> 5) & 0x3f;

	/* Seconds after minute (0-59).  FAT counts 2-second intervals, so
	 * multiply by 2. */
	u16 seconds = (time & 0x1f) * 2;

	struct tm tm = {
		.tm_sec = seconds,
		.tm_min = minutes,
		.tm_hour = hours,
		.tm_mday = day,
		.tm_mon = month,
		.tm_year = year,
		.tm_wday = 0,
		.tm_yday = 0,
		.tm_isdst = -1,
	};
	return mktime(&tm);
}

/* Transfer the attributes of a FAT file into standard UNIX format (`struct
 * stat'). */
int
fat_file_to_stbuf(struct fat_file *file, struct stat *stbuf)
{
	memset(stbuf, 0, sizeof(*stbuf));
	stbuf->st_nlink = 1;
	if (file->dentry.attribs & FILE_ATTRIBUTE_DIRECTORY)
		stbuf->st_mode |= S_IFDIR;
	else
		stbuf->st_mode |= S_IFREG;
	if (file->dentry.attribs & FILE_ATTRIBUTE_READONLY)
		stbuf->st_mode |= 0555;
	else
		stbuf->st_mode |= 0777;
	stbuf->st_size = file->dentry.file_size;
	stbuf->st_blocks = (stbuf->st_size + (1 << file->volume->cluster_order) - 1)
				>> file->volume->cluster_order;
	stbuf->st_blksize = 1 << file->volume->cluster_order;
	stbuf->st_ctime = fat_time_to_unix_time(file->dentry.create_date,
						file->dentry.create_time);
	stbuf->st_atime = fat_time_to_unix_time(file->dentry.last_access_date, 0);
	stbuf->st_mtime = fat_time_to_unix_time(file->dentry.last_modified_date,
						file->dentry.last_modified_time);
	return 0;
}

/* Do common initializations on a `struct fat_file' (other than members that can
 * be set to zero as their default value). */
void
fat_file_init(struct fat_file *file, struct fat_volume *vol)
{
	file->volume = vol;
	INIT_LIST_HEAD(&file->lru_list);
}

/* Read the cluster numbers we are going to need for the read operation from the
 * FAT. */
static int
fat_file_preload_clusters(struct fat_file *file, u32 end_cluster_idx)
{
	u32 *cluster_cache;
	u32 next_cluster;

 	cluster_cache = file->file.cluster_cache;
	while (file->file.last_known_cluster_idx < end_cluster_idx) {
		next_cluster = fat_next_cluster(file->volume,
						cluster_cache[file->file.last_known_cluster_idx]);
		if (next_cluster == FAT_CLUSTER_END_OF_CHAIN)
			return -EIO;
		cluster_cache[++file->file.last_known_cluster_idx] = next_cluster;
	}
	return 0;
}

static size_t
do_fat_file_pread(struct fat_file *file, void *buf, size_t size, off_t offset,
		  u32 start_cluster_idx, u32 end_cluster_idx)
{
	size_t bytes_remaining;
	struct fat_volume *vol;
	u32 i;

	DEBUG("start_cluster_idx=%u, end_cluster_idx=%u",
	      start_cluster_idx, end_cluster_idx);
	bytes_remaining = size;
	vol = file->volume;
	for (i = start_cluster_idx; i <= end_cluster_idx; i++) {
		size_t cluster_needed_bytes;
		off_t data_offset;
		ssize_t bytes_read;
		u32 next_cluster;

		next_cluster = file->file.cluster_cache[i];
		cluster_needed_bytes = min((1 << vol->cluster_order) -
					      (offset &
					       ((1 << vol->cluster_order) - 1)),
					    bytes_remaining);
		data_offset = fat_data_cluster_offset(vol, next_cluster) +
				(offset & ((1 << vol->cluster_order) - 1));
		bytes_read = full_pread(vol->fd, buf,
					cluster_needed_bytes, data_offset);
		if (bytes_read != cluster_needed_bytes)
			break;
		bytes_remaining -= bytes_read;
		buf += bytes_read;
		offset += bytes_read;
	}
	return size - bytes_remaining;
}

/* Read @size bytes from the FAT file @file at offset @offset, storing the
 * result into the buffer @buf.  Returns a negative error number on failure,
 * otherwise the number of bytes read (short count only on EOF). */
ssize_t
fat_file_pread(struct fat_file *file, void *buf, size_t size, off_t offset)
{
	u32 start_cluster_idx;
	u32 end_cluster_idx;
	off_t last_byte;
	u16 cluster_order;
	int ret;

	if (size == 0)
		return 0;

	if (offset > file->dentry.file_size)
		return -EOVERFLOW;

	cluster_order = file->volume->cluster_order;
 	start_cluster_idx = offset >> cluster_order;
	size = min(size, file->dentry.file_size - offset);
	if (size == 0)
		return 0;
 	last_byte = offset + size - 1;
	end_cluster_idx = last_byte >> cluster_order;
	ret = fat_file_preload_clusters(file, end_cluster_idx);
	if (ret)
		return ret;
	return do_fat_file_pread(file, buf, size, offset,
				 start_cluster_idx, end_cluster_idx);
}
