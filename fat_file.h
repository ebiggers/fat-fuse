#ifndef _FAT_FILE_H
#define _FAT_FILE_H

#include "fat_types.h"
#include "avl_tree.h"
#include "list.h"
#include <sys/types.h>

struct fat_volume;
struct stat;

/* Flags that go in the @attribs field of FAT directory entries. */
#define FILE_ATTRIBUTE_READONLY		0x00000001
#define FILE_ATTRIBUTE_HIDDEN		0x00000002
#define FILE_ATTRIBUTE_SYSTEM		0x00000004
#define FILE_ATTRIBUTE_VOLUME		0x00000008
#define FILE_ATTRIBUTE_DIRECTORY	0x00000010
#define FILE_ATTRIBUTE_ARCHIVE		0x00000020

/* FAT directory entry (in memory) */
struct fat_dir_entry {
	char name[8 + 1 + 3 + 1]; /* filename; with extension, if present; null-terminated */
	u8 attribs;
	u32 create_time;
	u32 create_date;
	u32 last_access_date;
	u32 last_modified_time;
	u32 last_modified_date;
	u32 start_cluster;
	u32 file_size;
};

/* Wrapper around a FAT directory entry that contains members used to put it in
 * data structures, and to use it as a file handle */
struct fat_file {
	/* The data from the actual FAT directory ntrey */
	struct fat_dir_entry dentry;

	/* Node in balanced binary search tree of parent directory's children.
	 */
	struct avl_tree_node sibling_node;

	union {
		/* Valid only for directories */
		struct {
			/* Balanced binary search tree of children.  Valid only
			 * if children_read == 1. */
			struct avl_tree_node *children;
		} dir;

		/* Valid only for non-directory files */
		struct {
			/* Number of clusters that this file is supposed to be,
			 * based on the file_size given in the directory entry
			 * */
			u32 num_clusters;

			/* Index, within this file, of the cluster with greatest
			 * offset within this file we have stored in the
			 * cluster_cache. */
			u32 last_known_cluster_idx;

			/* Table of length @num_clusters long that maps the
			 * indices of this file's clusters to their actual
			 * indices in the filesystem. */
			u32 *cluster_cache;
		} file;
	};
	/* List node used to (sometimes) insert this file into a
	 * least-recently-used list of directories for the FAT volume. */
	struct list_head lru_list;

	/* Pointer to parent file, or NULL if this is the root directory */
	struct fat_file *parent;

	/* Pointer to the FAT volume containing this file */
	struct fat_volume *volume;

	/* Current number of open file descriptors to this file */
	u32 num_times_opened : 31;

	/* True iff the children of this file have been read into memory.
	 * Always 0 for non-directories. */
	u32 children_read : 1;

	/* Current number of open file descriptors to this file and all
	 * decendents */
	u32 subdir_num_times_opened;
};

extern int
fat_dir_read_children(struct fat_file *dir);

extern ssize_t
fat_file_pread(struct fat_file *file, void *buf, size_t size, off_t offset);

extern struct fat_file *
fat_pathname_to_file(struct fat_volume *vol, const char *path);

extern void
fat_destroy_file_tree(struct fat_file *root);

extern int
fat_file_alloc_cluster_cache(struct fat_file *file);

extern void
fat_file_free_cluster_cache(struct fat_file *file);

extern int
fat_file_to_stbuf(struct fat_file *file, struct stat *stbuf);

extern void
fat_file_inc_num_times_opened(struct fat_file *file);

extern void
fat_file_dec_num_times_opened(struct fat_file *file);

#define FAT_FILE(avl_node) \
	avl_tree_entry((avl_node), struct fat_file, sibling_node)

/* Iterate through the children of a FAT directory.  Only valid if the children
 * have already been read into memory (_dir->children_read == 1) */
#define fat_dir_for_each_child(_child, _dir)				\
	avl_tree_for_each_in_order((_child), (_dir)->dir.children,	\
				   struct fat_file, sibling_node)

/* Iterate through the children of a FAT directory, safe against removal of
 * children.  Only valid if the children have already been read into memory
 * (_dir->children_read == 1) */
#define fat_dir_for_each_child_safe(_child, _dir)			\
	avl_tree_for_each_in_postorder((_child), (_dir)->dir.children,	\
				       struct fat_file, sibling_node)

static inline bool
fat_file_is_root(const struct fat_file *file)
{
	return file->parent == NULL;
}

static inline bool
fat_file_is_directory(const struct fat_file *file)
{
	return (file->dentry.attribs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

extern void
fat_file_init(struct fat_file *file, struct fat_volume *vol);

#endif /* _FAT_FILE_H */
