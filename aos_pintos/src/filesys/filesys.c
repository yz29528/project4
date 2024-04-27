
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
/* Partition that contains the file system. */
#define NAME_LEN NAME_MAX*5
struct block *fs_device;

static void do_format (void);
bool parse_path(char *path, struct dir **sup_dir, char **file_name, bool *is_directory);
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
bool filesys_chdir (const char * name){
    bool success = false,is_directory;
    struct dir *sup_dir=NULL;
    char *file_name=(char *) malloc(NAME_LEN + 1);
    struct dir *tmp_dir=NULL;
    if(is_root(name)){
        tmp_dir= dir_open_root ();
    }else if(parse_path(name, &sup_dir, &file_name, &is_directory)){
        tmp_dir=dir_open_subdir(sup_dir, file_name);

    }
    if (tmp_dir!=NULL){
        dir_close(thread_current()->cur_dir);
        thread_current()->cur_dir=tmp_dir;
        success=true;
    }
    dir_close(sup_dir);
    free(file_name);
    return success;
}

bool filesys_mkdir (const char * name){
    bool success = false,is_directory;
    struct dir *sup_dir=NULL;
    //printf("___path is__%s__\n",name);
    char *file_name=(char *) malloc(NAME_LEN + 1);
    if(!is_root(name) && parse_path(name, &sup_dir, &file_name, &is_directory)){

       success= dir_create_subdir(sup_dir, file_name);
    }

    dir_close(sup_dir);
    free(file_name);
    return success;
}
/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create (const char *name, off_t initial_size)
{
#ifdef FILESYS
    bool success = false,is_directory;
struct dir *sup_dir=NULL;
char *file_name= (char *) malloc(NAME_LEN + 1);
//printf("create_subfile_____________\n");
 if(!is_root(name)&&parse_path(name, &sup_dir, &file_name, &is_directory)){
    // printf("create_subfile_____is_root(name)&&parse_path________\n");
    if (!is_directory){
        //printf("create_subfile_____!is_directory________\n");
     success= dir_create_subfile(sup_dir, file_name, initial_size);
    }
 }
 dir_close(sup_dir);
 free(file_name);
return success;
#else
    block_sector_t inode_sector = 0;
    struct dir *dir = dir_open_root ();
    bool success = (dir != NULL && free_map_allocate (1, &inode_sector) &&
                    inode_create (inode_sector, initial_size) &&
                    dir_add (dir, name, inode_sector));
    if (!success && inode_sector != 0)
        free_map_release (inode_sector, 1);

    dir_close (dir);

    return success;
#endif
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *filesys_open (const char *name)
{
#ifdef FILESYS
    bool is_directory;
struct dir *sup_dir=NULL;
char *file_name= (char *) malloc(NAME_LEN + 1);
struct file* ret=NULL;
  if (is_root(name))
  {

      ret=file_open(inode_open(ROOT_DIR_SECTOR));
       //dir_print_dir(sup_dir);
      ret->dir=dir_open_root();
    return ret;
  }
  else if(parse_path(name, &sup_dir, &file_name, &is_directory)){
    // dir_print_dir(sup_dir);
    // printf("__open_path is__%s___name is_%s_\n",name,file_name);
    struct dir *tmp_dir=dir_open_subdir(sup_dir, file_name);
    if (tmp_dir!=NULL){
       ret=file_open(inode_reopen(dir_get_inode(tmp_dir)));
       ret->dir=dir_open(dir_get_inode(tmp_dir));
       dir_close(tmp_dir);
    }
    else {
        ret=dir_open_subfile(sup_dir, file_name);
        if(is_directory)
            ret = NULL;
    }

 }
   if (ret!=NULL && inode_get_symlink (file_get_inode(ret)))
    {
        char target[15];
        inode_read_at (file_get_inode(ret), target, NAME_LEN + 1, 0);
        dir_close(sup_dir);
        //printf("___open a file: %s__address is__%p________________\n",file_name,ret);
        free(file_name);
        file_close(ret);
        return filesys_open (target);
    }


dir_close(sup_dir);
  //printf("___open a file: %s__address is__%p________________\n",file_name,ret);
 free(file_name);
return ret;
#else
    struct dir *dir = dir_open_root ();
    struct inode *inode = NULL;

    if (dir != NULL)
        dir_lookup (dir, name, &inode);
    dir_close (dir);

    if (inode == NULL)
        return NULL;

    if (inode_get_symlink (inode))
    {
        char target[15];
        inode_read_at (inode, target, NAME_LEN + 1, 0);
        struct dir *root = dir_open_root ();
        if (!dir_lookup (root, target, &inode)){
            return NULL;
        }
        dir_close (root);
    }

    return file_open (inode);
#endif
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove (const char *name)
{
#ifdef FILESYS
    bool success = false,is_directory;
struct dir *sup_dir=NULL;
char *file_name = (char *) malloc(NAME_LEN + 1);
 if(!is_root(name)&&parse_path(name, &sup_dir, &file_name, &is_directory)){
     success= dir_check_and_remove(sup_dir, file_name);
 }
 //else printf("______!__parse_path(name, &sup_dir, &file_name, &is_directory)______________\n");
 dir_close(sup_dir);
 free(file_name);
return success;
#else
    struct dir *dir = dir_open_root ();
    bool success = dir != NULL && dir_remove (dir, name);
    dir_close (dir);

    return success;
#endif
}

/* Creates symbolic link LINKPATH to target file TARGET
   Returns true if symbolic link created successfully,
   false otherwise. */
bool filesys_symlink (char *target, char *linkpath)
{
    ASSERT (target != NULL && linkpath != NULL);
    bool success = filesys_create (linkpath, 15);
    struct file *symlink = filesys_open (linkpath);
    inode_set_symlink (file_get_inode (symlink), true);
    inode_write_at (file_get_inode (symlink), target, NAME_LEN + 1, 0);
    file_close (symlink);
    return success;
}

int filesys_stat(char *pathname, void *buf){
    bool is_directory;
    int ret=-1;
    struct dir *sup_dir=NULL;
    char *file_name = (char *) malloc(NAME_LEN + 1);
    if(!is_root(pathname)&&parse_path(pathname, &sup_dir, &file_name, &is_directory)){
        struct file* file=dir_open_subfile(sup_dir, file_name);
    //struct stat *stat = malloc (sizeof (struct stat));
        ret= inode_stat(file_get_inode(file),buf);
        file_close(file);
    //memcpy (buf, stat, sizeof (struct stat));
    }
    return ret;
};

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


/*
 * Check whether a single file/dir name is valid
 * Only check the length and '/'
 * */
/*
bool check_filedir_name(const char *name)
{
    if (name == NULL)
        return false;
    for (int i = 0; i < READDIR_MAX_LEN + 1; i++)
    {
        if (name[i] == '/')
            return false;
        if (name[i] == '\0')
            return true;
    }
    return false;
}
*/
/*
 * Check whether the name is '/'.
 * */
bool is_root(const char *name){
    return name != NULL
           &&strlen(name)>=1
           &&name[0] == '/'
           && name[1] == '\0';
}

/*
 * Paser non root path to a form as:
 * previous directory + target file/dir name
 * is_dir is true if it's surely a dir, false if unknown.
 * if return true, prev_dir MUST be closed after use this function
 * */

bool parse_path(char *path, struct dir **sup_dir, char **file_name, bool *is_directory)
{
/*
    int length = strlen(path);
    if (length == 0||path[0] == '\0') {
        //printf("____length == 0||path[0] ==__");
        return false;
    }
    char *path_copy = (char *) malloc(length + 1);
    strlcpy(path_copy, path, length + 1);
// check the tail to check whether it is a dir.
    *is_directory = false;
    if (path_copy[length - 1] == '/') {
        *is_directory = true;
        if (length <= 1) {
            free(path_copy);
            return false;
        }
        path_copy[--length] = '\0';
    }

    if (path_copy[0] == '/') {
//absolute path
        *sup_dir = dir_open_root();
    } else {
//relative path
        *sup_dir = dir_reopen(thread_current()->cur_dir);
    }

    char *save_ptr, *str = strtok_r(path_copy, "/", &save_ptr), *next_str = NULL;

    while (str != NULL) {
        next_str = strtok_r(NULL, "/", &save_ptr);
        if (next_str != NULL) {
            struct dir *tmp_dir = *sup_dir;
            *sup_dir = dir_open_subdir(*sup_dir, str);
            dir_close(tmp_dir);
            if (*sup_dir == NULL) {
                free(path_copy);
                return false;
            }
        } else {
                //printf("____NAME_LEN + 1__%d___%s_%d_",NAME_LEN + 1,str,strlen(str));
            strlcpy(*file_name, str, strlen(str) + 1);
            free(path_copy);
            printf("___path is__%s___name is_%s_\n",path,file_name);
            return true;
        }
        str = next_str;
    }

    free(path_copy);
    return false;
 * */

   bool debug=!true;
    if(debug)printf("path is_________________%s\n", path);
    *is_directory = false; // init it to false;
//
    // copy the full path
    int length = strlen(path);
    if (length == 0){
        if(debug)printf("__defore_length == 0_____\n");
        return false;
    }
    char *path_copy = malloc(length + 1);
    strlcpy(path_copy, path, length + 1);

    // check the tail to check whether it is surely a dir.
    if(length > 0 && path_copy[length - 1] == '/')
    {
        *is_directory = true;
        length--;
        ASSERT(length > 0); // non-root dir, length shouldn't be 0 here.
        path_copy[length] = '\0';
    }

    // length 0 is invalid.
    if (length == 0)
    {
        if(debug)printf("__after_length == 0_____\n");
        free(path_copy);
        return false;
    }

    if (path_copy[0] == '/')
        *sup_dir = dir_open_root();
    else
        *sup_dir = dir_reopen(thread_current()->cur_dir);

    //split token by '/'
    char *token, *save_ptr, *next_token;
    for (token = strtok_r(path_copy, "/", &save_ptr); ;token = next_token)
    {

        ASSERT(token != NULL);
        next_token = strtok_r(NULL, "/", &save_ptr);
        if (next_token == NULL) // token is the purename in path
        {
            strlcpy(*file_name, token, strlen(token) + 1);
            if(debug)printf("___path is__%s___name is_%s_\n",path,*file_name);
            break;
        }else{
            struct dir *tmp_dir = *sup_dir;
            if(debug)printf("___open__subdir_ token is_%s_\n",token);
            if(debug)dir_print_dir(*sup_dir);
            *sup_dir = dir_open_subdir(*sup_dir, token);
            dir_close(tmp_dir);
            if (*sup_dir == NULL)
            {
                if(debug)printf("___*sup_dir == NULL_____\n");
                free(path_copy);
                return false;
            }
        }
    }
    free(path_copy);
    return true;

}