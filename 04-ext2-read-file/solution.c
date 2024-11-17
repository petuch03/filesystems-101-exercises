#include <solution.h>
#include <fs_malloc.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define EXT2_SUPER_MAGIC 0xEF53
#define DIRECT_POINTERS 12
#define SUPERBLOCK_OFFSET 1024
#define BLOCK_GROUP_DESC_OFFSET 2048

struct fs_blockgroup_descriptor {
    uint32_t address_of_block_usage_bitmap;
    uint32_t address_of_inode_usage_bitmap;
    uint32_t address_of_inode_table;
    uint16_t unallocated_blocks_counts;
    uint16_t unallocated_inodes_counts;
    uint16_t directories_in_group_count;
    uint8_t unused[14];
};

struct fs_superblock {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_us_reserved_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size_kbytes;
    uint32_t s_log_frag_size_kbytes;
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
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t s_uuid[16];
    char s_volume_name[16];
    char s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;
    uint8_t s_prealloc_blocks;
    uint8_t s_prealloc_dir_blocks;
    uint16_t s_padding1;
    uint8_t s_journal_uuid[16];
    uint32_t s_journal_inum;
    uint32_t s_journal_dev;
    uint32_t s_last_orphan;
    uint8_t s_reserved[788];
};

struct fs_inode {
    uint16_t type_and_permissions;
    uint16_t user_id;
    uint32_t size_lower;
    uint32_t last_access_time;
    uint32_t creation_time;
    uint32_t last_modification_time;
    uint32_t deletion_time;
    uint16_t group_id;
    uint16_t hard_link_count;
    uint32_t disk_sector_count;
    uint32_t flags;
    uint32_t os_specific_value_1;
    uint32_t direct_block_pointers[DIRECT_POINTERS];
    uint32_t singly_indirect_block;
    uint32_t doubly_indirect_block;
    uint32_t triply_indirect_block;
    uint32_t generation_number;
    uint32_t extended_attribute_block;
    uint32_t size_upper_or_directory_acl;
    uint32_t fragment_block_address;
    uint8_t os_specific_value_2[12];
    char extra_data[];
};

struct ext2_fs {
    struct fs_superblock *superblock;
    int fd;
};

struct ext2_blkiter {
    int fd;
    uint32_t iterator_block_index;
    uint32_t block_size;
    struct fs_inode *inode;
    struct fs_blockgroup_descriptor *blockgroup_descriptor;
    int64_t single_indirect_block_cache_id;
    int64_t double_indirect_block_cache_id;
    int64_t triple_indirect_block_cache_id;
    char indirect_pointer_cache[];
};

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

static int write_data(int fd, const void *buffer, size_t size, off_t offset) {
    const char *buf = buffer;
    size_t total_written = 0;

    while (total_written < size) {
        ssize_t written = pwrite(fd, buf + total_written,
                               size - total_written,
                               offset + total_written);
        if (written < 0) {
            return -errno;
        }
        total_written += written;
    }
    return 0;
}

int dump_file(int img, int inode_nr, int out) {
    int result = 0;

    // Read superblock
    struct fs_superblock *sb = fs_xmalloc(sizeof(struct fs_superblock));
    if (pread(img, sb, sizeof(struct fs_superblock), SUPERBLOCK_OFFSET) != sizeof(struct fs_superblock)) {
        fs_xfree(sb);
        return -EIO;
    }
    if (sb->s_magic != EXT2_SUPER_MAGIC) {
        fs_xfree(sb);
        return -EINVAL;
    }

    // Calculate block size
    uint32_t block_size = 1024 << sb->s_log_block_size_kbytes;

    // Read inode
    uint32_t block_group = (inode_nr - 1) / sb->s_inodes_per_group;
    uint32_t local_inode = (inode_nr - 1) % sb->s_inodes_per_group;

    // Find inode table location
    uint32_t group_desc_size = 32; // Standard size of group descriptor
    uint32_t group_desc_offset = BLOCK_GROUP_DESC_OFFSET + (block_group * group_desc_size);

    uint8_t group_desc[32];
    if (pread(img, group_desc, sizeof(group_desc), group_desc_offset) != sizeof(group_desc)) {
        fs_xfree(sb);
        return -EIO;
    }

    uint32_t inode_table_block = *(uint32_t*)(&group_desc[8]); // Offset of inode table block number in group descriptor
    uint32_t inode_offset = (inode_table_block * block_size) + (local_inode * sb->s_inode_size);

    struct fs_inode *inode = fs_xmalloc(sizeof(struct fs_inode));
    if (pread(img, inode, sizeof(struct fs_inode), inode_offset) != sizeof(struct fs_inode)) {
        fs_xfree(inode);
        fs_xfree(sb);
        return -EIO;
    }

    // Allocate block buffer
    char *block_buffer = fs_xmalloc(block_size);
    uint64_t remaining_size = inode->size_lower;
    off_t write_offset = 0;

    // Process direct blocks
    for (int i = 0; i < DIRECT_POINTERS && inode->direct_block_pointers[i] && remaining_size > 0; i++) {
        result = read_block(img, block_buffer, inode->direct_block_pointers[i], block_size);
        if (result < 0) {
            goto cleanup;
        }

        uint32_t to_write = (remaining_size < block_size) ? remaining_size : block_size;
        result = write_data(out, block_buffer, to_write, write_offset);
        if (result < 0) {
            goto cleanup;
        }
        remaining_size -= to_write;
        write_offset += to_write;
    }

    // Process singly indirect block if needed and if there's remaining data
    if (inode->singly_indirect_block && remaining_size > 0) {
        uint32_t *indirect_block = fs_xmalloc(block_size);
        result = read_block(img, indirect_block, inode->singly_indirect_block, block_size);
        if (result < 0) {
            fs_xfree(indirect_block);
            goto cleanup;
        }

        for (uint32_t i = 0; i < block_size/4 && indirect_block[i] && remaining_size > 0; i++) {
            result = read_block(img, block_buffer, indirect_block[i], block_size);
            if (result < 0) {
                fs_xfree(indirect_block);
                goto cleanup;
            }

            uint32_t to_write = (remaining_size < block_size) ? remaining_size : block_size;
            result = write_data(out, block_buffer, to_write, write_offset);
            if (result < 0) {
                fs_xfree(indirect_block);
                goto cleanup;
            }
            remaining_size -= to_write;
            write_offset += to_write;
        }
        fs_xfree(indirect_block);
    }

    // Process doubly indirect block if needed and if there's remaining data
    if (inode->doubly_indirect_block && remaining_size > 0) {
        uint32_t *double_indirect = fs_xmalloc(block_size);
        result = read_block(img, double_indirect, inode->doubly_indirect_block, block_size);
        if (result < 0) {
            fs_xfree(double_indirect);
            goto cleanup;
        }

        for (uint32_t i = 0; i < block_size/4 && double_indirect[i] && remaining_size > 0; i++) {
            uint32_t *indirect_block = fs_xmalloc(block_size);
            result = read_block(img, indirect_block, double_indirect[i], block_size);
            if (result < 0) {
                fs_xfree(indirect_block);
                fs_xfree(double_indirect);
                goto cleanup;
            }

            for (uint32_t j = 0; j < block_size/4 && indirect_block[j] && remaining_size > 0; j++) {
                result = read_block(img, block_buffer, indirect_block[j], block_size);
                if (result < 0) {
                    fs_xfree(indirect_block);
                    fs_xfree(double_indirect);
                    goto cleanup;
                }

                uint32_t to_write = (remaining_size < block_size) ? remaining_size : block_size;
                result = write_data(out, block_buffer, to_write, write_offset);
                if (result < 0) {
                    fs_xfree(indirect_block);
                    fs_xfree(double_indirect);
                    goto cleanup;
                }
                remaining_size -= to_write;
                write_offset += to_write;
            }
            fs_xfree(indirect_block);
        }
        fs_xfree(double_indirect);
    }

cleanup:
    fs_xfree(block_buffer);
    fs_xfree(inode);
    fs_xfree(sb);
    return result;
}