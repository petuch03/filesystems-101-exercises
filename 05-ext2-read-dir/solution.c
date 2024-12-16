#include <solution.h>
#include <fs_malloc.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define EXT2_SUPER_MAGIC 0xEF53
#define POINTERS 12
#define SUPERBLOCK_OFFSET 1024
#define BLOCK_GROUP_DESC_OFFSET 2048

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
    uint32_t direct_block_pointers[POINTERS];
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


struct ext2_dir_entry {
    uint32_t inode;        // Inode number
    uint16_t rec_len;      // Directory entry length
    uint8_t  name_len;     // Name length
    uint8_t  file_type;    // File type
    char     name[];       // File name (NULL-terminated)
} __attribute__((packed));

// Block iterator structure
struct ext2_blockiter {
    int fd;                     // File descriptor of the filesystem image
    uint32_t block_size;        // Block size in bytes
    uint32_t curr_idx;          // Current block index
    uint32_t *curr_block;       // Current block being processed
    struct fs_inode *inode;     // Inode being processed
    uint32_t indirect_block;    // Current indirect block number
    char *block_buffer;         // Buffer for indirect blocks
    int level;                  // Current indirection level (0=direct, 1=single)
};

#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR     2

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

// Initialize block iterator
static struct ext2_blockiter *ext2_blockiter_init(int fd, struct fs_inode *inode, uint32_t block_size) {
    struct ext2_blockiter *iter = fs_xmalloc(sizeof(struct ext2_blockiter));
    iter->fd = fd;
    iter->block_size = block_size;
    iter->curr_idx = 0;
    iter->inode = inode;
    iter->indirect_block = 0;
    iter->block_buffer = fs_xmalloc(block_size);
    iter->level = 0;
    iter->curr_block = NULL;
    return iter;
}

// Get next block number
static int ext2_blockiter_next(struct ext2_blockiter *iter, uint32_t *blkno) {
    if (iter->curr_idx < POINTERS) {
        // Direct blocks
        *blkno = iter->inode->direct_block_pointers[iter->curr_idx++];
        if (*blkno == 0) {
            if (iter->inode->singly_indirect_block) {
                // Switch to indirect blocks
                iter->level = 1;
                iter->curr_idx = 0;
                if (read_block(iter->fd, iter->block_buffer, iter->inode->singly_indirect_block, iter->block_size) < 0) {
                    return -EIO;
                }
                iter->curr_block = (uint32_t *)iter->block_buffer;
                return ext2_blockiter_next(iter, blkno);
            }
            return 0;
        }
        return 1;
    } else if (iter->level == 1) {
        // Indirect blocks
        *blkno = iter->curr_block[iter->curr_idx++];
        if (*blkno == 0 || iter->curr_idx >= iter->block_size / 4) {
            return 0;
        }
        return 1;
    }
    return 0;
}

// Cleanup block iterator
static void ext2_blockiter_cleanup(struct ext2_blockiter *iter) {
    if (iter) {
        fs_xfree(iter->block_buffer);
        fs_xfree(iter);
    }
}

int dump_dir(int img, int inode_nr) {
    int result = 0;
    uint32_t blkno;

    struct fs_superblock *sb = fs_xmalloc(sizeof(struct fs_superblock));
    if (pread(img, sb, sizeof(struct fs_superblock), SUPERBLOCK_OFFSET) != sizeof(struct fs_superblock)) {
        fs_xfree(sb);
        return -EIO;
    }
    if (sb->s_magic != EXT2_SUPER_MAGIC) {
        fs_xfree(sb);
        return -EINVAL;
    }

    uint32_t block_size = 1024 << sb->s_log_block_size_kbytes;

    uint32_t block_group = (inode_nr - 1) / sb->s_inodes_per_group;
    uint32_t local_inode = (inode_nr - 1) % sb->s_inodes_per_group;

    uint32_t group_desc_size = 32;
    uint32_t group_desc_offset = BLOCK_GROUP_DESC_OFFSET + (block_group * group_desc_size);

    uint8_t group_desc[32];
    if (pread(img, group_desc, sizeof(group_desc), group_desc_offset) != sizeof(group_desc)) {
        fs_xfree(sb);
        return -EIO;
    }

    uint32_t inode_table_block = *(uint32_t*)(&group_desc[8]);
    uint32_t inode_offset = (inode_table_block * block_size) + (local_inode * sb->s_inode_size);

    struct fs_inode *inode = fs_xmalloc(sizeof(struct fs_inode));
    if (pread(img, inode, sizeof(struct fs_inode), inode_offset) != sizeof(struct fs_inode)) {
        fs_xfree(inode);
        fs_xfree(sb);
        return -EIO;
    }

    char *block_buffer = fs_xmalloc(block_size);
    struct ext2_blockiter *iter = ext2_blockiter_init(img, inode, block_size);

    while ((result = ext2_blockiter_next(iter, &blkno)) > 0) {
        result = read_block(img, block_buffer, blkno, block_size);
        if (result < 0) {
            break;
        }

        char *ptr = block_buffer;
        while (ptr < block_buffer + block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)ptr;
            if (entry->inode == 0 || entry->rec_len == 0) {
                break;
            }

            char *name = fs_xmalloc(entry->name_len + 1);
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            if (entry->file_type == EXT2_FT_REG_FILE) {
                report_file(entry->inode, 'f', name);
            } else if (entry->file_type == EXT2_FT_DIR) {
                report_file(entry->inode, 'd', name);
            }

            fs_xfree(name);
            ptr += entry->rec_len;
        }
    }

    ext2_blockiter_cleanup(iter);
    fs_xfree(block_buffer);
    fs_xfree(inode);
    fs_xfree(sb);
    return (result < 0) ? result : 0;
}