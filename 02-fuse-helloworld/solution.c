#define _FILE_OFFSET_BITS 64
#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 31
#endif

#include <fuse.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define FILE_PATH "/hello"
#define FILE_MODE 0755
#define READ_ONLY_MODE 0400

static char* generate_greeting() {
    static char message[64];
    snprintf(message, sizeof(message), "hello, %d\n", fuse_get_context()->pid);
    return message;
}

int fs_attributes(const char* path, struct stat* statbuf, struct fuse_file_info* fi) {
    (void) fi;
    memset(statbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        statbuf->st_mode = S_IFDIR | FILE_MODE;
        statbuf->st_nlink = 2;
        statbuf->st_uid = geteuid();
        statbuf->st_gid = getegid();
        return 0;
    } else if (strcmp(path, FILE_PATH) == 0) {
        statbuf->st_mode = S_IFREG | READ_ONLY_MODE;
        statbuf->st_nlink = 1;
        statbuf->st_size = strlen(generate_greeting());
        statbuf->st_uid = geteuid();
        statbuf->st_gid = getegid();
        return 0;
    }
    return -ENOENT;
}

int fs_open(const char* path, struct fuse_file_info* fi) {
    if (strcmp(path, FILE_PATH) != 0) return -ENOENT;
    if ((fi->flags & O_ACCMODE) != O_RDONLY) return -EROFS;
    return 0;
}

int fs_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    (void) fi;
    if (strcmp(path, FILE_PATH) != 0) return -ENOENT;
    const char* content = generate_greeting();
    size_t content_len = strlen(content);
    if (offset >= content_len) return 0;
    if (size > content_len - offset) size = content_len - offset;
    memcpy(buf, content + offset, size);
    return size;
}

int fs_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    (void) path;
    (void) buf;
    (void) size;
    (void) offset;
    (void) fi;
    return -EROFS;
}

int fs_list_dir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi, enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    if (strcmp(path, "/") == 0) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_mode = S_IFDIR | FILE_MODE;
        filler(buf, ".", &st, 0, 0);
        filler(buf, "..", &st, 0, 0);
        
        st.st_mode = S_IFREG | READ_ONLY_MODE;
        st.st_size = strlen(generate_greeting());
        filler(buf, "hello", &st, 0, 0);
        return 0;
    }
    return -ENOENT;
}

int fs_truncate(const char* path, mode_t mode, struct fuse_file_info* fi) {
    (void) path;
    (void) mode;
    (void) fi;
    return -EROFS;
}

static struct fuse_operations hellofs_ops = {
    .getattr = fs_attributes,
    .readdir = fs_list_dir,
    .open = fs_open,
    .read = fs_read,
    .write = fs_write,
    .truncate = fs_truncate,
    .chmod = fs_truncate,
    .create = fs_truncate,
};

int helloworld(const char *mntp)
{
	char *argv[] = {"exercise", "-f", (char *)mntp, NULL};
	return fuse_main(3, argv, &hellofs_ops, NULL);
}