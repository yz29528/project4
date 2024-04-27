#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "lib/kernel/stdio.h"
#include "lib/stdio.h"
#include "lib/string.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "devices/input.h"
#include "devices/block.h"

static void syscall_handler (struct intr_frame *);
static bool valid_ptr (void *);

static struct semaphore filesys_mutex; // Ensure mutual exclusion to filesys

const int MAX_OPEN_FILES = 1024; // Max open files per process

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  sema_init (&filesys_mutex, 1);
}

/* Check if pointers to arguments are valid */
static int check_args (void *esp, int num_args)
{
  int *int_esp = (int *) esp;
  for (int i = 0; i < num_args; i++)
    {
      int_esp += 1;
      if (!valid_ptr (int_esp))
        {
          return 1;
        }
    }
  return 0;
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  if (!valid_ptr (f->esp))
    {
      exit (-1);
    }
  int syscall_num = *(int *) f->esp;

  switch (syscall_num)
    {
      case SYS_HALT:
        halt ();
        break;
      case SYS_EXIT:
        if (check_args (f->esp, 1))
          {
            exit (-1);
          }
        int status = *((int *) f->esp + 1);
        exit (status);
        break;
      case SYS_EXEC:
        if (check_args (f->esp, 1))
          {
            exit (-1);
          }
        char *filename = *((char **) f->esp + 1);
        f->eax = exec (filename);
        break;
      case SYS_WAIT:
        if (check_args (f->esp, 1))
          {
            exit (-1);
          }
        pid_t pid = *((pid_t *) f->esp + 1);
        f->eax = wait (pid);
        break;
      case SYS_CREATE:
        if (check_args (f->esp, 3))
          {
            exit (-1);
          }
        void *file_c = *((char **) f->esp + 1);
        unsigned initial_size = *((int *) f->esp + 2);
        f->eax = create (file_c, initial_size);
        break;
      case SYS_REMOVE:
        if (check_args (f->esp, 1))
          {
            exit (-1);
          }
        void *file_r = *((char **) f->esp + 1);
        f->eax = remove (file_r);
        break;
      case SYS_OPEN:
        if (check_args (f->esp, 1))
          {
            exit (-1);
          }
        char *file_o = *((char **) f->esp + 1);
        f->eax = open (file_o);
        break;
      case SYS_FILESIZE:
        if (check_args (f->esp, 1))
          {
            exit (-1);
          }
        unsigned fd_f = *((int *) f->esp + 1);
        f->eax = filesize (fd_f);
        break;
      case SYS_READ:
        if (check_args (f->esp, 3))
          {
            exit (-1);
          }
        int fd_r = *((int *) f->esp + 1);
        void *buffer_r = *((char **) f->esp + 2);
        unsigned size_r = *((int *) f->esp + 3);
        f->eax = read (fd_r, buffer_r, size_r);
        break;
      case SYS_WRITE:
        if (check_args (f->esp, 3))
          {
            exit (-1);
          }
        int fd_w = *((int *) f->esp + 1);
        void *buffer_w = *((char **) f->esp + 2);
        unsigned size_w = *((int *) f->esp + 3);
        f->eax = write (fd_w, buffer_w, size_w);
        break;
      case SYS_SEEK:
        if (check_args (f->esp, 2))
          {
            exit (-1);
          }
        int fd_s = *((int *) f->esp + 1);
        unsigned position = *((unsigned *) f->esp + 2);
        seek (fd_s, position);
        break;
      case SYS_TELL:
        if (check_args (f->esp, 1))
          {
            exit (-1);
          }
        int fd_t = *((int *) f->esp + 1);
        f->eax = tell (fd_t);
        break;
      case SYS_CLOSE:
        if (check_args (f->esp, 1))
          {
            exit (-1);
          }
        int fd_c = *((int *) f->esp + 1);
        close (fd_c);
        break;
      case SYS_SYMLINK:
        if (check_args (f->esp, 2))
          {
            exit (-1);
          }
        char *target = *((char **) f->esp + 1);
        char *linkpath = *((char **) f->esp + 2);
        f->eax = symlink (target, linkpath);
        break;
        case SYS_MKDIR:
            if (check_args (f->esp, 1))
            {
                exit (-1);
            }
            char *dir1 = *((char **) f->esp + 1);
            //printf("f->eax = mkdir (dir1)__________________\n");
            f->eax = mkdir (dir1);
            break;
        case SYS_CHDIR:
            if (check_args (f->esp, 1))
            {
                exit (-1);
            }
            char *dir2 = *((char **) f->esp + 1);
            f->eax = chdir (dir2);
            break;
        case SYS_READDIR:
            if (check_args (f->esp, 2))
            {
                exit (-1);
            }
            int fd_readdir = *((int *) f->esp + 1);
            char *name_readdir = *((char **) f->esp + 2);
            f->eax = readdir(fd_readdir,name_readdir);
            break;
        case SYS_ISDIR:
            if (check_args (f->esp, 1))
            {
                exit (-1);
            }
            int fd_isdir = *((int *) f->esp + 1);
            f->eax = isdir(fd_isdir);
            break;
        case SYS_INUMBER:
            if (check_args (f->esp, 1))
            {
                exit (-1);
            }
            int fd_inumber = *((int *) f->esp + 1);
            f->eax = inumber(fd_inumber);
            break;
    }
}

bool isdir (int fd){
    if (fd >= MAX_OPEN_FILES || fd == 1||fd==2 || fd < 0)
    {
        return false;
    }
    struct file **fds = thread_current ()->fd_table;
    if (fds[fd] == NULL)
    {
        return false;
    }
    sema_down (&filesys_mutex);
    bool suc=inode_get_directory(file_get_inode(fds[fd]));
    sema_up (&filesys_mutex);
    return suc;
}

int inumber (int fd){
    if (fd >= MAX_OPEN_FILES || fd == 1||fd==2 || fd < 0)
    {
        return false;
    }
    struct file **fds = thread_current ()->fd_table;
    if (fds[fd] == NULL)
    {
        return false;
    }
    sema_down (&filesys_mutex);
    int ret=inode_get_sector(file_get_inode(fds[fd]));
    sema_up (&filesys_mutex);
    return ret;
}

int stat (char *pathname, void *buf){


    return -1;
}



bool readdir (int fd,char *name){
    //printf("_______1________\n");
    if (fd >= MAX_OPEN_FILES ||  fd < 0)
    {
        printf("___fd id is %d ___",fd);
        return false;
    }
    //printf("_______2________\n");//NAME_MAX + 1
    if (!valid_ptr ((void *) name))
    {
        //printf("_______3________\n");
        exit (-1);
    }
    if (!valid_ptr(name + READDIR_MAX_LEN)) {
        exit (-1);
       //printf("_______4________\n");
    }
    struct file **fds = thread_current ()->fd_table;
    if (fds[fd] == NULL)
    {
       // printf("_______5________\n");
        return false;
    }
    sema_down (&filesys_mutex);
    //printf("dir try toopen___\n");
    //struct inode *in=file_get_inode();
    //printf("inode->open_cnt is_%d__\n",in->open_cnt);
    struct dir *dir=fds[fd]->dir;
    //printf("inode->open_cnt is_%d__\n",in->open_cnt);
    //if(dir!=NULL)
    //printf("dir IS NOT NULL__________\n");
   //dir_print_dir(dir);
    bool suc = dir_readdir (dir, name);
    /*
    if(suc)
        printf("dir_readdir sec______________%s__\n",name);
    else
       printf("dir_readdir fail________________\n");
       */
   // printf("inode->open_cnt is_%d__\n",in->open_cnt);
  //  printf("inode->open_cnt is_%d__\n",in->open_cnt);
    sema_up (&filesys_mutex);

    return suc;
}

bool mkdir(char *dir){
    //;
    if (!valid_ptr ((void *) dir) )
    {
        //printf("mkdir(char *dir) fail________________\n");
        exit (-1);
    }
    sema_down (&filesys_mutex);

    bool suc = filesys_mkdir(dir);
    sema_up (&filesys_mutex);
   // if(!suc)
    //printf("mkdir(char *dir) fail________________\n");
    //else
     //   printf("mkdir(char *dir) suc_______________\n");
    return suc;
}

bool chdir(char *dir){
    if (!valid_ptr ((void *) dir))
    {
        exit (-1);
    }
    sema_down (&filesys_mutex);
    bool suc = filesys_chdir(dir);
    sema_up (&filesys_mutex);
    return suc;
}

void halt () { shutdown_power_off (); }

void exit (int status)
{
  printf ("%s: exit(%d)\n", thread_current ()->name, status);

  // Free all of exiting thread's children
  struct list *our_children = &(thread_current ()->children);
  if (!list_empty (our_children))
    {
      struct list_elem *curr;
      for (curr = list_front (our_children); curr != list_end (our_children);)
        {
          struct child *curr_item = list_entry (curr, struct child, elem);
          curr_item->child_thread->parent = NULL;
          curr = curr->next;
          free (curr_item);
        }
    }

  // Close all open files
  int fd = 2;
  struct file **fds = thread_current ()->fd_table;
  while (fd < MAX_OPEN_FILES)
    {
      if (fds[fd] != NULL)
        {
          close (fd);
        }
      fd++;
    }

  /* Find current thread in parents children data structure and communicate exit
  status */
  if (thread_current ()->parent)
    {
      struct list *children = &(thread_current ()->parent->children);
      if (!list_empty (children))
        {
          struct list_elem *curr;
          struct child *curr_item;
          for (curr = list_front (children); curr != list_end (children);
               curr = list_next (curr))
            {
              curr_item = list_entry (curr, struct child, elem);
              if (curr_item->pid == thread_current ()->tid)
                {
                  curr_item->exit_status = status;
                  // Let waiting parent know you are finished
                  sema_up (&curr_item->exited);
                  break;
                }
            }
        }
    }
  // Re-enable writes to executable associated w/ this process
  close (0);
  palloc_free_page (thread_current ()->fd_table);
  thread_exit ();
}

pid_t exec (const char *cmd_line)
{
  if (!valid_ptr ((void *) cmd_line))
    {
      exit (-1);
    }

  int tid = process_execute (cmd_line);

  sema_down (&thread_current ()->child_created); // wait for child creation
  tid = !thread_current ()->success ? -1 : tid;  // if exec fails tid = -1
  thread_current ()->success = false;            // reset success value
  return tid;
}

int wait (pid_t pid) { return process_wait (pid); }

bool create (const char *file, unsigned initial_size)
{
  if (!valid_ptr ((void *) file))
    {
      exit (-1);
    }

  sema_down (&filesys_mutex);
  bool opened = filesys_create (file, initial_size);
  sema_up (&filesys_mutex);

  return opened;
}

bool remove (const char *file)
{
  if (!valid_ptr ((void *) file))
    {
      exit (-1);
    }
  sema_down (&filesys_mutex);
  bool removed = filesys_remove (file);
  sema_up (&filesys_mutex);
  return removed;
}

int open (const char *filename)
{
  if (!valid_ptr ((void *) filename))
    {
      exit (-1);
    }

  struct file **fds = thread_current ()->fd_table;
  int fd = 2;
  struct file *curr = fds[fd];

  // Find open spot in table to open file
  while (curr != NULL)
    {
      curr = fds[++fd];
      if (fd == MAX_OPEN_FILES)
        {
          return -1;
        }
    }

  sema_down (&filesys_mutex);
  struct file *file = filesys_open (filename);
  sema_up (&filesys_mutex);
  if (file == NULL)
    {
      return -1;
    }

  fds[fd] = file;
    //printf("___open a file: %s__fd is__%d________________\n",filename,fd);
  return fd;
}

int filesize (int fd)
{
  struct file *file = thread_current ()->fd_table[fd];
  if (file == NULL)
    {
      return 0;
    }
  sema_down (&filesys_mutex);
  int length = file_length (file);
  sema_up (&filesys_mutex);
  return length;
}

int read (int fd, void *buffer, unsigned size)
{
  if (fd >= MAX_OPEN_FILES || fd == 1 || fd < 0)
    {
      return -1;
    }
  if (!valid_ptr ((void *) buffer) || !valid_ptr ((char *) buffer + size))
    {
      exit (-1);
    }

  struct file *file = thread_current ()->fd_table[fd];
  if (file == NULL)
    {
      return 0;
    }
  unsigned bytes_read = 0;

  // Read from stdin
  if (fd == 0)
    {
      for (unsigned i = 0; i < size; i++)
        {
          *((char *) buffer + i) = input_getc ();
          bytes_read++;
        }
    }
  else // Read from file
    {
      sema_down (&filesys_mutex);
      bytes_read = file_read (file, buffer, size);
      sema_up (&filesys_mutex);
    }

  return bytes_read;
}

int write (int fd, const void *buffer, unsigned size)
{
  if (!valid_ptr ((void *) buffer) || !valid_ptr ((char *) buffer + size))
    {
      exit (-1);
    }
  if (fd >= MAX_OPEN_FILES || fd <= 0)
    {
      return 0;
    }
  if (fd == 1) // Write to stdout
    {
      putbuf (((char *) buffer), (size_t) size);
      return size;
    }

  struct file *file = thread_current ()->fd_table[fd];
  if (file == NULL || file->deny_write)
    {
      return 0;
    }
    if(inode_get_directory(file_get_inode(file))){
        return -1;
    }
  sema_down (&filesys_mutex);
  unsigned bytes_written = file_write (file, buffer, size);
  sema_up (&filesys_mutex);
  return bytes_written;
}

void seek (int fd, unsigned position)
{
  if (fd >= MAX_OPEN_FILES || fd == 1)
    {
      return;
    }
  struct file *file = thread_current ()->fd_table[fd];
  if (file == NULL)
    {
      return;
    }
  sema_down (&filesys_mutex);
  file_seek (file, position);
  sema_up (&filesys_mutex);
}

unsigned tell (int fd)
{
  if (fd >= MAX_OPEN_FILES)
    {
      return 0;
    }
  struct file *file = thread_current ()->fd_table[fd];
  if (file == NULL)
    {
      return 0;
    }
  sema_down (&filesys_mutex);
  unsigned pos = file_tell (file);
  sema_up (&filesys_mutex);
  return pos;
}

void close (int fd)
{
  struct file **fds = thread_current ()->fd_table;
  if (fd >= MAX_OPEN_FILES)
    {
      return;
    }
  sema_down (&filesys_mutex);
  file_close (fds[fd]);
  fds[fd] = NULL;
  sema_up (&filesys_mutex);
}

int symlink (char *target, char *linkpath)
{
  sema_down (&filesys_mutex);
  struct file *target_file = filesys_open (target);
  sema_up (&filesys_mutex);

  if (target_file == NULL)
    {
      return -1;
    }

  sema_down (&filesys_mutex);
  bool success = filesys_symlink (target, linkpath);
  sema_up (&filesys_mutex);

  return success ? 0 : -1;
}

bool valid_ptr (void *ptr)
{
  return ptr && !is_kernel_vaddr (ptr) &&
         pagedir_get_page (thread_current ()->pagedir, ptr);
}