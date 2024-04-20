#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

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
bool chdir (char *dir);
bool mkdir (char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);
int stat (char *pathname, void *buffer);

#endif /* userprog/syscall.h */
