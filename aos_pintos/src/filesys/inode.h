#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"

#define NULL_SECTOR -1
struct bitmap;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
    block_sector_t table; /* BLOCK_SECTOR_TABLE. */
    off_t length;         /* File size in bytes. */
    unsigned magic;       /* Magic number. */
    bool is_symlink;      /* True if symbolic link, false otherwise. */
    bool is_directory;    /* True if directory, false otherwise. */
    uint8_t unused[498];  /* Not used. */
};
struct cache_entry{
    block_sector_t sector;
    char buffer[BLOCK_SECTOR_SIZE];
    struct hash_elem he;
    struct list_elem le;
};
struct inode
{
    struct list_elem elem;  /* Element in inode list. */
    block_sector_t sector;  /* Sector number of disk location. */
    int open_cnt;           /* Number of openers. */
    bool removed;           /* True if deleted, false otherwise. */
    int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
    struct inode_disk data; /* Inode content. */
};
void cache_init (void);
void cache_read (struct block *block, block_sector_t sector, void *buffer);
void cache_write (struct block *block, block_sector_t sector, void *buffer);
void cache_done (void);

void inode_init (void);
bool inode_create (block_sector_t, off_t);
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

void inode_set_directory (struct inode *inode);
bool inode_get_directory (struct inode *inode);
int inode_get_sector(struct inode *inode);
#endif /* filesys/inode.h */
