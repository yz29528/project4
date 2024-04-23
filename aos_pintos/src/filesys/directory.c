#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* A directory. */
struct dir
{
  struct inode *inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry
{
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create (block_sector_t sector, size_t entry_cnt)
{
  bool success = inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);
  if (!success) {
    return false;
  }

  // The first (offset 0) dir entry is for parent directory; do self-referencing
  // Actual parent directory will be set on execution of dir_add()
  struct dir *dir = dir_open(inode_open(sector));
  ASSERT (dir != NULL);
  struct dir_entry e;
  e.inode_sector = sector;
  if (inode_write_at(dir->inode, &e, sizeof e, 0) != sizeof e) {
    success = false;
  }
  dir_close (dir);

  return success;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *dir_open (struct inode *inode)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens the directory for given path. */
struct dir *dir_open_path(const char *path) {
  // Make a copy of the path to tokenize
  int path_length = strlen(path);
  char s[path_length + 1];
  strlcpy(s, path, path_length + 1);

  // Handle relative paths
  struct dir *directory;
  if (path[0] == '/') { // Path is an absolute path
    directory = dir_open_root();
  } else {
    struct thread *t = thread_current();
    if (t->cwd == NULL) { // This may happen for non-process threads (main)
      directory = dir_open_root();
    } else {
      directory = dir_reopen(t->cwd);
    }
  }

  // Tokenize and traverse the directory tree
  char *token, *p;
  for (token = strtok_r(s, "/", &p); token != NULL; token = strtok_r(NULL, "/", &p)) {
    struct inode *inode = NULL;
    if(! dir_lookup(directory, token, &inode)) {
      dir_close(directory);
      return NULL; // directory doesn't exist
    }

    struct dir *next = dir_open(inode);
    if (next == NULL) {
      dir_close(directory);
      return NULL;
    }

    // if (inode_is_directory(next->inode)) {
      dir_close(directory);
      directory = next;
    // }
  }

  // Prevent opening removed directories
  if (inode_is_removed(dir_get_inode(directory))) {
    dir_close(directory);
    return NULL;
  }

  return directory;
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *dir_reopen (struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *dir_get_inode (struct dir *dir) { return dir->inode; }

bool dir_is_empty (const struct dir *dir) {
  struct dir_entry e;

  for (off_t ofs = sizeof e; /* 0-pos is for parent directory */
       inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) {
    if (e.in_use) {
      return false;
    }
  }
  return true;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup (const struct dir *dir, const char *name,
                    struct dir_entry *ep, off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp (name, e.name))
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup (const struct dir *dir, const char *name, struct inode **inode)
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (strcmp(name, ".") == 0) {
    // Current directory
    *inode = inode_reopen(dir->inode);
  } else if (strcmp(name, "..") == 0) {
    // Parent directory
    inode_read_at(dir->inode, &e, sizeof e, 0);
    *inode = inode_reopen(e.inode_sector);
  } else if (lookup(dir, name, &e, NULL)) {
    // Normal lookup
    *inode = inode_open (e.inode_sector);
  } else {
    *inode = NULL;
  }

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add (struct dir *dir, const char *name, block_sector_t inode_sector, bool is_dir)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  if (is_dir) {
    // The parent directory (dir) has a child directory (inode_sector)
    struct dir *child_dir = dir_open(inode_open(inode_sector));
    if (child_dir == NULL) {
      goto done;
    }

    // e is the parent directory entry
    e.inode_sector = inode_get_inumber(dir_get_inode(dir));

    if (inode_write_at(child_dir->inode, &e, sizeof e, 0) != sizeof e) {
      dir_close (child_dir);
      goto done;
    }
    dir_close (child_dir);
  }

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Don't remove non-empty directory. */
  if (inode_is_directory (inode)) {
    struct dir *target = dir_open(inode); // directory to be removed, "dir" is base directory
    bool is_empty = dir_is_empty(target);
    dir_close(target);
    if (!is_empty) {
      goto done;
    }
  }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  return false;
}

/*
 * Split path.
 * directory and filename should be preallocated buffers
 */
void split_path_filename(const char *path, char *directory, char *filename) {
  int path_length = strlen(path);
  char *s = (char*)malloc(sizeof(char) * (path_length + 1));
  memcpy(s, path, sizeof(char) * (path_length + 1));

  // Handle absolute paths
  char *dir = directory;
  if (path_length > 0 && path[0] == '/') {
    if (dir) {
      *dir++ = '/';
    }
  }

  // Tokenize
  char *token, *p, *last_token = "";
  for (token = strtok_r(s, "/", &p); token != NULL; token = strtok_r(NULL, "/", &p)) {
    // Append last_token into directory
    int token_length = strlen(last_token);
    if (dir && token_length > 0) {
      memcpy(dir, last_token, sizeof(char) * token_length);
      dir[token_length] = '/';
      dir += token_length + 1;
    }

    last_token = token;
  }

  // Terminate the directory with a null char
  if (dir) {
    *dir = '\0';
  }
  memcpy(filename, last_token, sizeof(char) * (strlen(last_token) + 1));
  free(s);
}