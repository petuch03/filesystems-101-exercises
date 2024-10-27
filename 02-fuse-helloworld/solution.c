#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 31
#endif

#include <fuse.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

static char* build_message(void) {
    static char buf[128];
    pid_t current_pid = fuse_get_context()->pid;
    snprintf(buf, sizeof(buf), "hello, %d\n", current_pid);
    return buf;
}

static int fs_attributes(const char* path, struct stat* stats, struct fuse_file_info* fi) {
    (void) fi;

    if (strcmp(path, "/") == 0) {
        stats->st_mode = S_IFDIR | 0755;
        stats->st_nlink = 2;
        stats->st_size = 0;
        stats->st_uid = geteuid();
        stats->st_gid = getegid();
        return 0;
    }

    if (strcmp(path, "/hello") == 0) {
        stats->st_mode = S_IFREG | 0400;
        stats->st_nlink = 1;
        stats->st_size = strlen(build_message());
        stats->st_uid = geteuid();
        stats->st_gid = getegid();
        return 0;
    }

    return -ENOENT;
}

static int fs_list_dir(const char* path, void* buffer, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info* fi, enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    struct stat st = {0};
    st.st_mode = S_IFDIR | 0755;
    filler(buffer, ".", &st, 0, 0);
    filler(buffer, "..", &st, 0, 0);

    st.st_mode = S_IFREG | 0400;
    st.st_size = strlen(build_message());
    filler(buffer, "hello", &st, 0, 0);

    return 0;
}

static int fs_open(const char* path, struct fuse_file_info* fi) {
    if (strcmp(path, "/hello") != 0)
        return -ENOENT;
    if ((fi->flags & O_ACCMODE) != O_RDONLY)
        return -EROFS;
    return 0;
}

static int fs_read(const char* path, char* buf, size_t size, off_t offset,
                  struct fuse_file_info* fi) {
    if (strcmp(path, "/hello") != 0)
        return -ENOENT;
    if ((fi->flags & O_ACCMODE) != O_RDONLY)
        return -ENOENT;

    const char* content = build_message();
    size_t content_len = strlen(content);

    if (offset >= content_len)
        return 0;

    if (size > content_len - offset)
        size = content_len - offset;

    memcpy(buf, content + offset, size);
    return size;
}

static int fs_write(const char* path, const char* buf, size_t size,
                   off_t offset, struct fuse_file_info* fi) {
    (void) path;
    (void) buf;
    (void) size;
    (void) offset;
    (void) fi;
    return -EROFS;
}

static int fs_truncate(const char* path, off_t size, struct fuse_file_info* fi) {
    (void) path;
    (void) size;
    (void) fi;
    return -EROFS;
}

static int fs_chmod(const char* path, mode_t mode, struct fuse_file_info* fi) {
    (void) path;
    (void) mode;
    (void) fi;
    return -EROFS;
}

static int fs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    (void) path;
    (void) mode;
    (void) fi;
    return -EROFS;
}

static struct fuse_operations fs_ops = {
    .getattr = fs_attributes,
    .readdir = fs_list_dir,
    .open = fs_open,
    .read = fs_read,
    .write = fs_write,
    .truncate = fs_truncate,
    .chmod = fs_chmod,
    .create = fs_create,
};

int helloworld(const char *mntp)
{
	char *argv[] = {"exercise", "-f", (char *)mntp, NULL};
	return fuse_main(3, argv, &hellofs_ops, NULL);
}