#include <solution.h>
#include <ntfs-3g/ntfs.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define BUFFER_SIZE 4096

int dump_file(int img, const char *path, int out)
{
	ntfs_volume *vol;
	ntfs_file *file;
	ntfs_inode *inode;
	s64 bytes_read;
	char buffer[BUFFER_SIZE];
	ssize_t write_result;
	int ret = 0;

	/* Mount the NTFS volume from the image file descriptor */
	vol = ntfs_mount_fd(img, 0);
	if (!vol) {
		return -errno;
	}

	/* Open the file using libntfs-3g */
	file = ntfs_file_open(vol, path, O_RDONLY);
	if (!file) {
		ret = -errno;
		goto cleanup_volume;
	}

	/* Get the inode for additional file information if needed */
	inode = ntfs_pathname_to_inode(vol, NULL, path);
	if (!inode) {
		ret = -errno;
		goto cleanup_file;
	}

	/* Read from NTFS file and write to output descriptor */
	while ((bytes_read = ntfs_file_read(file, buffer, sizeof(buffer))) > 0) {
		write_result = write(out, buffer, bytes_read);
		if (write_result < 0) {
			ret = -errno;
			goto cleanup_inode;
		}
		if (write_result != bytes_read) {
			ret = -EIO;
			goto cleanup_inode;
		}
	}

	if (bytes_read < 0) {
		ret = -errno;
	}

	cleanup_inode:
		ntfs_inode_close(inode);
	cleanup_file:
		ntfs_file_close(file);
	cleanup_volume:
		ntfs_umount(vol, FALSE);
	return ret;
}