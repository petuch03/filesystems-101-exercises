#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

static const char *hello_path = "/hello";

static int hello_getattr(const char *path, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0775;
        stbuf->st_nlink = 2;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
    }
    else if (strcmp(path, hello_path) == 0) {
        stbuf->st_mode = S_IFREG | 0400;  // read-only for owner
        stbuf->st_nlink = 1;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
        stbuf->st_size = 128;  // approximate size, doesn't need to match exactly
    }
    else
        return -ENOENT;

    return 0;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    (void) fi;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, "hello", NULL, 0);

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
    int len = snprintf(content, sizeof(content), "hello, %d\n", (int)fuse_get_context()->pid);

    if (offset >= len)
        return 0;

    if (offset + size > len)
        size = len - offset;

    memcpy(buf, content + offset, size);
    return size;
}

static int hello_write(const char *path, const char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi)
{
    return -EROFS;  // Read-only filesystem
}

struct fuse_operations hellofs_ops = {
    .getattr    = hello_getattr,
    .readdir    = hello_readdir,
    .open       = hello_open,
    .read       = hello_read,
    .write      = hello_write,
};