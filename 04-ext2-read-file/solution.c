#include <solution.h>
#include <fs_malloc.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define EXT2_SUPER_MAGIC 0xEF53
#define BLOCK_SIZE 1024
#define INODE_SIZE 128

struct ext2_super_block {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_reserved_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
} __attribute__((packed));

struct ext2_inode {
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_reserved1;
    uint32_t i_block[15];
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_dir_acl;
    uint32_t i_faddr;
    uint32_t i_reserved2[3];
} __attribute__((packed));

static int read_block(int fd, void *buffer, uint32_t block_nr, uint32_t block_size) {
    ssize_t bytes_read = pread(fd, buffer, block_size, block_nr * block_size);
    if (bytes_read < 0) {
        return -errno;
    }
    if (bytes_read != (ssize_t)block_size) {
        return -EIO;
    }
    return 0;
}

static int write_data(int fd, const void *buffer, size_t size) {
    const char *buf = buffer;
    size_t total_written = 0;

    while (total_written < size) {
        ssize_t written = write(fd, buf + total_written, size - total_written);
        if (written < 0) {
            return -errno;
        }
        total_written += written;
    }
    return 0;
}

int dump_file(int img, int inode_nr, int out)
{
    struct ext2_super_block sb;
    ssize_t read_size = pread(img, &sb, sizeof(sb), 1024);
    if (read_size < 0) {
        return -errno;
    }
    if (read_size != sizeof(sb)) {
        return -EIO;
    }
    if (sb.s_magic != EXT2_SUPER_MAGIC) {
        return -EINVAL;
    }

    uint32_t block_size = 1024 << sb.s_log_block_size;

    uint32_t block_group = (inode_nr - 1) / sb.s_inodes_per_group;
    uint32_t inode_index = (inode_nr - 1) % sb.s_inodes_per_group;
    uint32_t block_group_offset = 2048 + (block_group * sizeof(struct ext2_inode) * sb.s_inodes_per_group);
    uint32_t inode_offset = block_group_offset + (inode_index * sizeof(struct ext2_inode));

    struct ext2_inode inode;
    read_size = pread(img, &inode, sizeof(inode), inode_offset);
    if (read_size < 0) {
        return -errno;
    }
    if (read_size != sizeof(inode)) {
        return -EIO;
    }

    char *block_buffer = fs_xmalloc(block_size);
    int result = 0;

    for (int i = 0; i < 12 && inode.i_block[i] && inode.i_size > 0; i++) {
        result = read_block(img, block_buffer, inode.i_block[i], block_size);
        if (result < 0) {
            fs_xfree(block_buffer);
            return result;
        }

        uint32_t to_write = (inode.i_size < block_size) ? inode.i_size : block_size;
        result = write_data(out, block_buffer, to_write);
        if (result < 0) {
            fs_xfree(block_buffer);
            return result;
        }
        inode.i_size -= to_write;
    }

    if (inode.i_block[12] && inode.i_size > 0) {
        uint32_t *indirect_block = fs_xmalloc(block_size);
        result = read_block(img, indirect_block, inode.i_block[12], block_size);
        if (result < 0) {
            fs_xfree(indirect_block);
            fs_xfree(block_buffer);
            return result;
        }

        for (uint32_t i = 0; i < block_size/4 && indirect_block[i] && inode.i_size > 0; i++) {
            result = read_block(img, block_buffer, indirect_block[i], block_size);
            if (result < 0) {
                fs_xfree(indirect_block);
                fs_xfree(block_buffer);
                return result;
            }

            uint32_t to_write = (inode.i_size < block_size) ? inode.i_size : block_size;
            result = write_data(out, block_buffer, to_write);
            if (result < 0) {
                fs_xfree(indirect_block);
                fs_xfree(block_buffer);
                return result;
            }
            inode.i_size -= to_write;
        }
        fs_xfree(indirect_block);
    }

    if (inode.i_block[13] && inode.i_size > 0) {
        uint32_t *double_indirect = fs_xmalloc(block_size);
        result = read_block(img, double_indirect, inode.i_block[13], block_size);
        if (result < 0) {
            fs_xfree(double_indirect);
            fs_xfree(block_buffer);
            return result;
        }

        for (uint32_t i = 0; i < block_size/4 && double_indirect[i] && inode.i_size > 0; i++) {
            uint32_t *indirect_block = fs_xmalloc(block_size);
            result = read_block(img, indirect_block, double_indirect[i], block_size);
            if (result < 0) {
                fs_xfree(indirect_block);
                fs_xfree(double_indirect);
                fs_xfree(block_buffer);
                return result;
            }

            for (uint32_t j = 0; j < block_size/4 && indirect_block[j] && inode.i_size > 0; j++) {
                result = read_block(img, block_buffer, indirect_block[j], block_size);
                if (result < 0) {
                    fs_xfree(indirect_block);
                    fs_xfree(double_indirect);
                    fs_xfree(block_buffer);
                    return result;
                }

                uint32_t to_write = (inode.i_size < block_size) ? inode.i_size : block_size;
                result = write_data(out, block_buffer, to_write);
                if (result < 0) {
                    fs_xfree(indirect_block);
                    fs_xfree(double_indirect);
                    fs_xfree(block_buffer);
                    return result;
                }
                inode.i_size -= to_write;
            }
            fs_xfree(indirect_block);
        }
        fs_xfree(double_indirect);
    }

    fs_xfree(block_buffer);
    return 0;
}