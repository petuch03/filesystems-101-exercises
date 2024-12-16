#pragma once

/**
   Implement this function to copy the content of a file at @path
   to a file descriptor @out. @path has no symlinks inside it.
   @img is a file descriptor of an open ext2 image.

   It suffices to support single- and double-indirect blocks.

   If a copy was successful, return 0. If an error occurred during
   a read or a write, return -errno.

   Do take care to return -ENOENT, -ENOTDIR and other errors that
   may happen during a path traversal.
*/
int dump_file(int img, const char *path, int out);
