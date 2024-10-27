#include <solution.h>
#include <fuse.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static int hello_getattr(const char *path, struct stat *st,
                        struct fuse_file_info *fi)
{
    (void)fi;
    memset(st, 0, sizeof(struct stat));

    //st->st_uid = getuid();
    //st->st_gid = getgid();

    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }

    if (strcmp(path, "/hello") == 0) {
        st->st_mode = S_IFREG | 0400;
        st->st_nlink = 1;
        st->st_size = 19;
        return 0;
    }

    return -ENOENT;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags)
{
    (void)offset;
    (void)fi;
    (void)flags;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, "hello", NULL, 0, 0);
//    filler(buf, ",", NULL, 0, 0);

    return 0;
}

static int hello_read(const char *path, char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    (void)fi;

    if (strcmp(path, "/hello") != 0)
        return -ENOENT;

    char content[64];
    int len = snprintf(content, sizeof(content), "hello, %d\n", fuse_get_context()->pid);

    if (offset >= len)
        return 0;

    if (offset + size > len)
        size = len - offset;

    memcpy(buf, content + offset, size);
    return size;
}

static int hello_open(const char *path, struct fuse_file_info *fi)
{
    if (strcmp(path, "/hello") != 0)
        return -ENOENT;

    if ((fi->flags & O_ACCMODE) != O_RDONLY)
        return -EROFS;

    return 0;
}

static const struct fuse_operations hellofs_ops = {
    .getattr = hello_getattr,
    .readdir = hello_readdir,
    .open = hello_open,
    .read = hello_read,
    //.write = NULL,
    //.create = NULL,
};

int helloworld(const char *mntp)
{
	char *argv[] = {"exercise", "-f", (char *)mntp, NULL};
	return fuse_main(3, argv, &hellofs_ops, NULL);
}
