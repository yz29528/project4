#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();
    cache_init();
  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done (void) {
    free_map_close ();
    cache_done();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create (const char *name, off_t initial_size, bool is_dir)
{
  block_sector_t inode_sector = 0;

  char directory[strlen(name)];
  char file_name[strlen(name)];
  split_path_filename(name, directory, file_name);
  struct dir *dir = dir_open_path(directory);

  bool success = (dir != NULL && free_map_allocate (1, &inode_sector) &&
                  inode_create (inode_sector, initial_size, is_dir) &&
                  dir_add (dir, file_name, inode_sector, is_dir));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);

  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *filesys_open (const char *name)
{
  int path_length = strlen(name);
  if (path_length == 0) {
    return NULL;
  }

  char directory[path_length + 1];
  char file_name[path_length + 1];
  split_path_filename(name, directory, file_name);
  struct dir *dir = dir_open_path (directory);

  struct inode *inode = NULL;

  if (dir == NULL) {
    return NULL;
  }

  if (strlen(file_name) > 0) {
    dir_lookup(dir, file_name, &inode);
    dir_close(dir);
  } else { // Filename is empty, just return the directory
    inode = dir_get_inode(dir);
  }

  if (inode == NULL || inode_is_removed(inode)) {
    return NULL;
  }

  if (inode_get_symlink (inode))
    {
      char target[15];
      inode_read_at (inode, target, NAME_MAX + 1, 0);
      struct dir *root = dir_open_root ();
      if (!dir_lookup (root, target, &inode))
        {
          return NULL;
        }
      dir_close (root);
    }

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove (const char *name)
{
  char directory[strlen(name)];
  char file_name[strlen(name)];
  split_path_filename(name, directory, file_name);
  struct dir *dir = dir_open_path (directory);

  bool success = dir != NULL && dir_remove(dir, file_name);
  dir_close (dir);

  return success;
}

/* Creates symbolic link LINKPATH to target file TARGET
   Returns true if symbolic link created successfully,
   false otherwise. */
bool filesys_symlink (char *target, char *linkpath)
{
  ASSERT (target != NULL && linkpath != NULL);
  bool success = filesys_create (linkpath, 15, false);
  struct file *symlink = filesys_open (linkpath);
  inode_set_symlink (file_get_inode (symlink), true);
  inode_write_at (file_get_inode (symlink), target, NAME_MAX + 1, 0);
  file_close (symlink);
  return success;
}

/* Change CWD for the current thread. */
bool filesys_chdir (const char *path) {
  struct dir *dir = dir_open_path(path);

  if (dir == NULL) {
    return false;
  }

  dir_close(thread_current()->cwd);
  thread_current()->cwd = dir;

  return true;
}

/* Formats the file system. */
static void do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}