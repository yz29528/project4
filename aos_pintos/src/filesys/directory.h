#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

struct inode;

/* Opening and closing directories. */
bool dir_create (block_sector_t sector, size_t entry_cnt);
struct dir *dir_open (struct inode *);
struct dir *dir_open_root (void);
struct dir *dir_reopen (struct dir *);
void dir_close (struct dir *);
struct inode *dir_get_inode (struct dir *);

/* Reading and writing. */
bool dir_lookup (const struct dir *, const char *name, struct inode **);
bool dir_add (struct dir *, const char *name, block_sector_t);
bool dir_remove (struct dir *, const char *name);
bool dir_readdir (struct dir *, char name[NAME_MAX + 1]);
bool dir_print_dir (struct dir *dir );
bool file_create(struct dir* cur_dir, char* name,bool is_directory ,off_t initial_size);

bool dir_check_and_remove(struct dir* cur_dir, char* name);
bool dir_is_empty (struct dir *dir );
struct dir* dir_open_subdir(struct dir* cur_dir, char* name);
struct file* dir_open_subfile(struct dir* cur_dir, char* name);
bool dir_create_subfile(struct dir* cur_dir, char* name, off_t initial_size);
bool dir_create_subdir(struct dir* cur_dir, char* name);
#endif /* filesys/directory.h */
