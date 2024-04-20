//
// Created by Administrator on 2024/4/20. LRU BASED CACHE
//

#include <lib/stdbool.h>
#include <string.h>
#include <lib/stdio.h>
#include <devices/timer.h>
#include "cache.h"
#include "filesys.h"
#include "threads/synch.h"

#define CACHE_SIZE 64

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
            entry= list_entry(list_pop_back (cache_queue),struct cache_entry,le);
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
                entry= list_entry(list_pop_back (cache_queue),struct cache_entry,le);
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
    while(!list_empty (cache_queue))
    {
    struct cache_entry *entry= list_entry(list_pop_back (cache_queue),struct cache_entry,le);
            block_write (fs_device,entry->sector, entry-> buffer);
            hash_delete (&cache_table,&entry->he);
            free(entry);
    }
}








