#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"
struct bitmap;

struct cache_entry{
    block_sector_t sector;
    char buffer[BLOCK_SECTOR_SIZE];
    struct hash_elem he;
    struct list_elem le;
};

void cache_init (void);
void cache_read (struct block *block, block_sector_t sector, void *buffer);
void cache_write (struct block *block, block_sector_t sector, void *buffer);
void cache_done (void);

void inode_init (void);
bool inode_create (block_sector_t, off_t, bool);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);
bool inode_get_symlink (struct inode *inode);
void inode_set_symlink (struct inode *inode, bool is_symlink);
bool inode_is_directory (const struct inode *inode);
bool inode_is_removed (const struct inode *inode);
off_t inode_bytes_written (struct inode *inode);

#endif /* filesys/inode.h */
