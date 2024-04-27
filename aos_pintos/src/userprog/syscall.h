#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#define READDIR_MAX_LEN 14
typedef int pid_t;
void syscall_init (void);
void halt (void);
void exit (int);
pid_t exec (const char *);
int wait (pid_t);
bool create (const char *, unsigned);
bool remove (const char *);
int open (const char *);
int filesize (int);
int read (int, void *, unsigned);
int write (int, const void *, unsigned);
void seek (int, unsigned);
unsigned tell (int);
void close (int);
int symlink (char *, char *);
bool mkdir(char *dir);
bool chdir(char *dir);
bool readdir (int fd,char *name);
int inumber (int fd);
bool isdir (int fd);
#endif /* userprog/syscall.h */
