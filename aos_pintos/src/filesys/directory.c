#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "filesys/file.h"
#define MIN_ENTRY 2
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
    bool success = inode_create (sector, (MIN_ENTRY + entry_cnt) * sizeof (struct dir_entry));
    struct inode* inode=inode_open (sector);
    if(success&&inode != NULL)
    {
        inode_set_directory(inode);
        struct dir *dir= dir_open (inode);
        ASSERT (dir_add(dir, ".", sector));
        // update it when put the dir tin another dir
        ASSERT (dir_add(dir, "..", sector));
        dir_close(dir);
    }
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

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup (const struct dir *dir, const char *name, struct dir_entry *ep, off_t *ofsp){
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

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
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

  if (success && inode_sector != inode_get_inumber(dir->inode)){
        struct inode* inode = inode_open (inode_sector);
        ASSERT (inode != NULL);

        //Set the super directory of the sub directcory.
        if(inode_get_directory(inode)){
            struct dir *sub_dir = dir_open (inode);
            lookup (sub_dir, "..", &e, &ofs);
            e.inode_sector = inode_get_inumber(dir->inode);
            inode_write_at(sub_dir->inode, &e, sizeof e, ofs);
            dir_close (sub_dir);
        }else{
            inode_close (inode);
        }
    }
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
      if (e.in_use&&(strcmp (e.name,".." )!=0 && strcmp (e.name,"." )!=0))
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  return false;
}
bool dir_print_dir (struct dir *dir )
{
    struct dir *dir_copy = dir_open(dir->inode);
    struct dir_entry e;
    char name[NAME_MAX + 1];
    while (dir_readdir(dir_copy,name))
    {
       printf("__dir_print_dir__%s__________\n",name);
    }
    free(dir_copy);
    return false;
}
//dir_create just create a dir with .. and .  by sector.
//we create a dir  and put it in cur_dir
static bool create_file_or_dir(struct dir* cur_dir, char* name,bool is_directory ,off_t initial_size UNUSED){
    ASSERT(cur_dir != NULL&&name != NULL);
    if (strlen(name) == 0)
        return false;
    block_sector_t sector = NULL_SECTOR;

    bool success;
    if(is_directory) {
        success = free_map_allocate(1, &sector)
                   && dir_create(sector, 0)
                   && dir_add(cur_dir, name, sector);
    }else {
        success = free_map_allocate(1, &sector)
                   && inode_create(sector, initial_size)
                   && dir_add(cur_dir, name, sector);
    }
    if (!success && sector != NULL_SECTOR)
        free_map_release(sector, 1);
    return success;
}

bool dir_create_subdir(struct dir* cur_dir, char* name){
    return create_file_or_dir(cur_dir,name,true ,0);
}

bool dir_create_subfile(struct dir* cur_dir, char* name, off_t initial_size){
    return create_file_or_dir(cur_dir,name, false ,initial_size);
}


struct file* dir_open_subfile(struct dir* cur_dir, char* name){
    ASSERT(cur_dir != NULL&&name != NULL)
    if (strlen(name) == 0)
        return NULL;
    struct inode* inode = NULL;
    if (!dir_lookup(cur_dir, name, &inode) || inode == NULL)
        return NULL;


    if (inode_get_directory(inode)){
        inode_close(inode);
        return NULL;
    }
    return  file_open(inode);
}

struct dir* dir_open_subdir(struct dir* cur_dir, char* name){
    ASSERT(cur_dir != NULL&&name != NULL)
    if (strlen(name) == 0)
        return NULL;
    struct inode* inode = NULL;
    if (!dir_lookup(cur_dir, name, &inode) || inode == NULL)
        return NULL;

//printf("try to open subdir %s \n",name);
    if (!inode_get_directory(inode)){
        inode_close(inode);
        //printf("subdir is not a dir: %s \n",name);
        return NULL;
    }
    return dir_open(inode);
}

bool dir_is_empty (struct dir *dir )
{
    struct dir_entry e;
    while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
        dir->pos += sizeof e;
        if (e.in_use&&(strcmp (e.name,"." )!=0 && strcmp (e.name,".." )!=0))
        {
            return false;
        }
    }
    return true;
}

//check
bool dir_check_and_remove(struct dir* cur_dir, char* name){
    ASSERT(cur_dir != NULL&&name != NULL && strlen(name) >= 0)
    struct inode* inode = NULL;

    bool debug= !true;

    if (!dir_lookup(cur_dir, name, &inode)){
        if(debug)printf("__!dir_lookup(cur_dir, name, &inode)r______________\n");
        return false;
    }
    if (inode == NULL) {

        if(debug)printf("__inode == NULL)_______\n");
        return false;
    }

    if (inode_get_directory(inode)) {
        if(debug)printf("__remove adir_______%s_______\n",name);
        if (inode->open_cnt>1) {

            if(debug)printf("__inode->open_cnt>0_______\n");
            return false;
        }
        //If you want to delete a dir the dir should not be cur dir
        if (inode_get_inumber(inode) ==
                inode_get_inumber(dir_get_inode(thread_current()->cur_dir)))
            //||inode_get_opencnt(inode) > 1
        {
            if(debug)printf("__If you want to delete a dir the dir should not be cur dir______________\n");
            inode_close(inode);
            return false;
        }
        //If you want to delete a dir ,the dir should be empty.
        // otherwise you should delete sub file at first .

        struct dir *dir_copy = dir_open(inode);
        if(debug)dir_print_dir(dir_copy);
        bool is_empty=dir_is_empty(dir_copy);
        dir_close(dir_copy);

        if(!is_empty) {
            if(debug)printf("____rmpty________\n");
            return false;
        }
    }else{
        if(debug)printf("__remove a file______________\n");
        inode_close(inode);
    }
    return dir_remove(cur_dir, name);
}

