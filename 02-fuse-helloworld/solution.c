#include "solution.h"
#include <fuse.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static const char *hello_path = "/hello";

static int hello_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi)
{
    (void) fi;
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0775;
        stbuf->st_nlink = 2;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
    }
    else if (strcmp(path, hello_path) == 0) {
        stbuf->st_mode = S_IFREG | 0400;
        stbuf->st_nlink = 1;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
        stbuf->st_size = 128;
    }
    else
        return -ENOENT;

    return 0;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags)
{
    (void) offset;
    (void) fi;
    (void) flags;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, "hello", NULL, 0, 0);

    return 0;
}

static int hello_open(const char *path, struct fuse_file_info *fi)
{
    if (strcmp(path, hello_path) != 0)
        return -ENOENT;

    if ((fi->flags & O_ACCMODE) != O_RDONLY)
        return -EROFS;

    return 0;
}

static int hello_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi)
{
    (void) fi;

    if (strcmp(path, hello_path) != 0)
        return -ENOENT;

    char content[128];
    ssize_t len = snprintf(content, sizeof(content), "hello, %d\n", (int)fuse_get_context()->pid);

    if (len < 0)
        return -EIO;

    if (offset >= len)
        return 0;

    if ((size_t)(offset + size) > (size_t)len)
        size = len - offset;

    memcpy(buf, content + offset, size);
    return size;
}

static int hello_write(const char *path, const char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi)
{
    (void) path;
    (void) buf;
    (void) size;
    (void) offset;
    (void) fi;
    return -EROFS;
}

struct fuse_operations hellofs_ops = {
    .getattr    = hello_getattr,
    .readdir    = hello_readdir,
    .open       = hello_open,
    .read       = hello_read,
    .write      = hello_write,
};

int helloworld(const char *mntp)
{
	char *argv[] = {"exercise", "-f", (char *)mntp, NULL};
	return fuse_main(3, argv, &hellofs_ops, NULL);
}