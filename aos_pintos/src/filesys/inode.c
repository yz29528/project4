
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/inode.h"
//#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"


/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define TABLE_SIZE 128
#define CACHE_SIZE 128
static char empty[BLOCK_SECTOR_SIZE];
static char zero[BLOCK_SECTOR_SIZE];

static struct hash cache_table;
static struct list cache_queue;
static struct lock cache_lock;
static size_t cnt;
static unsigned cache_hash(const struct hash_elem *e, void* aux UNUSED);
static bool cache_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

static bool cache_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
    struct cache_entry* fa = hash_entry(a,  struct cache_entry, he);
    struct cache_entry* fb = hash_entry(b,  struct cache_entry, he);
    return fa->sector < fb->sector;
}

static unsigned cache_hash(const struct hash_elem *e, void* aux UNUSED){
    struct cache_entry* f= hash_entry(e, struct cache_entry, he);
    return hash_bytes(&f->sector, sizeof(f->sector));
}

void cache_init ()
{
    hash_init(&cache_table, cache_hash, cache_hash_less, NULL);
    list_init(&cache_queue);
    lock_init(&cache_lock);
    cnt=0;
}

struct cache_entry* cache_find(block_sector_t sector) {
    struct cache_entry temp_entry;
    temp_entry.sector=sector;
    struct hash_elem* e= hash_find(&cache_table,&(temp_entry.he));
    return e!=NULL?hash_entry(e,struct cache_entry,he):NULL;
}

void cache_read (struct block *block,block_sector_t sector, void *buffer) {
    lock_acquire(&cache_lock);
    struct cache_entry *entry=cache_find(sector);
    if (entry == NULL){
        block_read (block, sector, buffer);
        if(cnt>=CACHE_SIZE){
            entry= list_entry(list_pop_back (&cache_queue),struct cache_entry,le);
            hash_delete (&cache_table,&entry->he);
            block_write (block, entry->sector, entry->buffer);
        }else{
            cnt++;
            entry = (struct cache_entry*)malloc(sizeof (struct cache_entry));
        }
        entry->sector = sector;
        memcpy (entry->buffer,buffer, BLOCK_SECTOR_SIZE);
        hash_insert(&cache_table, &entry->he);
        list_push_front(&cache_queue, &entry->le);
    }else{
        memcpy (buffer, entry->buffer, BLOCK_SECTOR_SIZE);
        list_remove(&entry->le);
        list_push_front(&cache_queue, &entry->le);
    }
    lock_release(&cache_lock);
}

void cache_write (struct block *block,block_sector_t sector, void *buffer) {
    lock_acquire(&cache_lock);
    struct cache_entry *entry=cache_find(sector);
    if (entry == NULL) {
        if(cnt>=CACHE_SIZE){
            entry= list_entry(list_pop_back (&cache_queue),struct cache_entry,le);
            hash_delete (&cache_table,&entry->he);
            block_write (block, entry->sector, entry->buffer);
        }else{
            cnt++;
            entry = (struct cache_entry*)malloc(sizeof (struct cache_entry));
        }
        entry->sector = sector;
        memcpy (entry->buffer,buffer, BLOCK_SECTOR_SIZE);
        hash_insert(&cache_table, &entry->he);
        list_push_front(&cache_queue, &entry->le);
    }else{
        memcpy (entry->buffer, buffer, BLOCK_SECTOR_SIZE);
        list_remove(&entry->le);
        list_push_front(&cache_queue, &entry->le);
    }
    lock_release(&cache_lock);
}

void cache_done () {
    while(!list_empty (&cache_queue))
    {
        struct cache_entry *entry= list_entry(list_pop_back (&cache_queue),struct cache_entry,le);
        block_write (fs_device,entry->sector, entry-> buffer);
        hash_delete (&cache_table,&entry->he);
        free(entry);
    }
}



/* Map the pos into table_index
*/
static off_t byte_to_tier1_index(off_t pos)
{
    return (pos >> 16) & (TABLE_SIZE - 1);
}

/* Map the pos into sector_index
*/
//2^9 =512   2^7=128   512/4=128
static off_t byte_to_tier2_index(off_t pos)
{
    return (pos >> 9) & (TABLE_SIZE - 1);
}

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */

block_sector_t byte_to_sector (struct inode *inode, off_t pos,bool write);
/*
 * Writing far beyond EOF can cause many blocks to be entirely zero.
 * In order to save space, some file systems do not allocate these
 * zeroed blocks at all until they are explicitly written to.
 * These file systems are said to support "sparse files."
 * You must adopt this strategy and implement sparse files.
 * */

int inode_stat (struct inode *inode,struct stat* stat) {
    /*size_t logical_size;             The logical file size of a file. */
    /*size_t physical_size;            The physical file size of a file. */
    /*block_sector_t inode_number;     The inode number of a file. */
    /* blkcnt_t blocks;                 Number of blocks allocated. */
    stat->inode_number=inode->sector;
    stat->logical_size=inode->data.length;
    stat->physical_size=inode->data.physical_size;
    stat->blocks=inode->data.blocks;
    return 0;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
block_sector_t byte_to_sector (struct inode *inode, off_t pos,bool write)
{
  ASSERT (inode != NULL);

    block_sector_t *tier1_table = calloc(TABLE_SIZE, sizeof(block_sector_t));
    block_sector_t *tier2_table = calloc(TABLE_SIZE, sizeof(block_sector_t));
    //if(pos<inode->data.initial_length){inode->data.blocks++;}
    if (pos >= inode->data.length) {
        if (!write) {
            free(tier1_table);
            free(tier2_table);
            return NULL_SECTOR;
        }
        //extend_file(inode,pos,tier2_table,tier2_table);
        inode->data.length = pos + 1;

    }


       cache_read (fs_device, inode->data.table, tier1_table);
       off_t t1=byte_to_tier1_index(pos);
      // printf("__pos:%d___t1 is__%d___\n",pos,t1);
    /*    */
     if(tier1_table[t1]==NULL_SECTOR){
         if(!free_map_allocate (1, &tier1_table[t1])){
             return NULL_SECTOR;
         }

         //printf("__create_tier1_table___t1 is__%d___\n",t1);
             cache_write (fs_device, tier1_table[t1], empty);
             cache_write (fs_device, inode->data.table, tier1_table);
     }

    cache_read (fs_device, tier1_table[t1], tier2_table);

    off_t t2=byte_to_tier2_index(pos);
    //printf("__pos:%d___t2 is__%d___\n",pos,t2);
    /*    */
    if(tier2_table[t2]==NULL_SECTOR){
        if(!free_map_allocate (1, &tier2_table[t2])) {
            return NULL_SECTOR;
        }
        inode->data.blocks++;
       // printf("__create_tier2_table__t1__is___%d__t2 is__%d___\n",t1,t2);
            cache_write (fs_device, tier2_table[t2], zero);
            cache_write (fs_device, tier1_table[t1], tier2_table);

    }

    block_sector_t sector = tier2_table[t2];

    if(sector==NULL_SECTOR)
    PANIC ("sector id -1 fails" );
    //printf("__pos:%d___sector is__%d___\n",pos,sector);
    free(tier1_table);
    free(tier2_table);
    cache_write(fs_device,inode->sector, &inode->data);
    return sector;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init (void) {
    list_init (&open_inodes);
    memset(empty, NULL_SECTOR, sizeof empty);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL) {
      //size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->initial_length= length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_symlink = false;
      disk_inode->is_directory = false;
      //disk_inode->table = NULL_SECTOR;
      disk_inode->physical_size=0;
      disk_inode->blocks=0;
      if (free_map_allocate(1, &disk_inode->table)) {


             if (length > 0) {
                 block_sector_t *tier1_table = calloc(TABLE_SIZE, sizeof(block_sector_t));
                 block_sector_t *tier2_table = calloc(TABLE_SIZE, sizeof(block_sector_t));
                 off_t tier1_table_end = byte_to_tier1_index(length - 1);
                 off_t tier2_table_end = byte_to_tier2_index(length - 1);
                 int i, j;


                 memset(tier1_table, NULL_SECTOR, TABLE_SIZE * sizeof(block_sector_t));

                 for (i = 0; i <= tier1_table_end; i++) {
                     // off_t r = (i == t1_t ? t2_t : TABLE_SIZE - 1);
                     off_t r = i == tier1_table_end ? tier2_table_end : (TABLE_SIZE - 1);//KEY

                     if (!free_map_allocate(1, &tier1_table[i])) {
                         free(tier1_table);
                         free(tier2_table);
                         free(disk_inode);
                         //printf("________tier1_table_[%d] fail\n", i);
                         return false;
                     }


                     memset(tier2_table, NULL_SECTOR, TABLE_SIZE * sizeof(block_sector_t));

                     for (j = 0; j <= r; j++) {
                         if (!free_map_allocate(1, &tier2_table[j])) {
                             free(tier1_table);
                             free(tier2_table);
                             free(disk_inode);
                             //printf("_______tier1_table_[%d]___tier2_table_[%d] fail\n", i, j);
                             return false;
                         }
                         cache_write(fs_device, tier2_table[j], zero);
                     }

                     cache_write(fs_device, tier1_table[i], tier2_table);
                 }


                 cache_write(fs_device, disk_inode->table, tier1_table);
                 free(tier1_table);
                 free(tier2_table);
             } else {
                 cache_write(fs_device, disk_inode->table, empty);
             }


          success = true;
      }

      cache_write(fs_device, sector, disk_inode);
      free(disk_inode);

  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
         off_t length = inode->data.length;

            if(length > 0)
            {
                block_sector_t *tier1_table = calloc(TABLE_SIZE, sizeof(block_sector_t));
                block_sector_t *tier2_table = calloc(TABLE_SIZE, sizeof(block_sector_t));

              off_t tier1_table_end = byte_to_tier1_index(length - 1);
              off_t tier2_table_end = byte_to_tier2_index(length - 1);
                int i, j;
                cache_read (fs_device,inode->data.table, tier1_table);

                for(i = 0; i <= tier1_table_end; i++)
                {
                    off_t r = (i == tier1_table_end
                            ? tier2_table_end : (TABLE_SIZE - 1));

                    if(tier1_table[i]==NULL_SECTOR)
                        continue;
                    cache_read (fs_device,tier1_table[i], tier2_table);
                    for(j = 0; j <= r; j++)
                    {
                        if(tier2_table[j]!=NULL_SECTOR) {
                            free_map_release(tier2_table[j], 1);
                        }
                    }
                        free_map_release(tier1_table[i], 1);
                    }

                free(tier1_table);
                free(tier2_table);
            }
            free_map_release (inode->sector, 1);
            if(inode->data.table!=NULL_SECTOR) {
                free_map_release(inode->data.table, 1);
            }
        }
      free (inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at (struct inode *inode, void *buffer_, off_t size,
                     off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset,false);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                      off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset,true);
      if(sector_idx==NULL_SECTOR){
          return NULL_SECTOR;
      }

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            cache_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
      inode->data.blocks++;
    }
  free (bounce);
    inode->data.physical_size+=bytes_written;
    cache_write (fs_device,inode->sector, &inode->data);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length (const struct inode *inode) { return inode->data.length; }

bool inode_get_symlink (struct inode *inode) {
  ASSERT (inode != NULL);
  return inode->data.is_symlink;
}

void inode_set_symlink (struct inode *inode, bool is_symlink)
{
  inode->data.is_symlink = is_symlink;
  cache_write (fs_device, inode->sector, &inode->data);
}

void inode_set_directory (struct inode *inode)
{
    inode->data.is_directory = true;
    cache_write (fs_device,inode->sector, &inode->data);
}

bool inode_get_directory (struct inode *inode){
    return inode->data.is_directory;
}
int inode_get_sector(struct inode *inode){
    return (int)inode->sector;
}
