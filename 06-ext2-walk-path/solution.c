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
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR     2

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


static int read_block(int fd, void *buffer, uint32_t block_nr, uint32_t block_size) {
    ssize_t bytes_read = pread(fd, buffer, block_size, block_nr * block_size);
    if (bytes_read < 0) return -errno;
    if (bytes_read != (ssize_t)block_size) return -EIO;
    return 0;
}

static int write_data(int fd, const void *buffer, size_t size, off_t offset) {
    const char *buf = buffer;
    size_t total_written = 0;
    while (total_written < size) {
        ssize_t written = pwrite(fd, buf + total_written, size - total_written, offset + total_written);
        if (written < 0) return -errno;
        total_written += written;
    }
    return 0;
}

static int find_file_in_dir(int img, uint32_t block_size, struct fs_inode *dir_inode,
                           const char *name, int *found_inode, uint8_t *file_type) {
    char *block_buffer = fs_xmalloc(block_size);
    int result = -ENOENT;
    uint64_t remaining_size = dir_inode->size_lower;

    for (int i = 0; i < 12 && dir_inode->direct_block_pointers[i] && remaining_size > 0; i++) {
        if (read_block(img, block_buffer, dir_inode->direct_block_pointers[i], block_size) < 0) {
            fs_xfree(block_buffer);
            return -EIO;
        }

        char *ptr = block_buffer;
        while (ptr < block_buffer + block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)ptr;
            if (entry->inode == 0 || entry->rec_len == 0) break;

            if (entry->name_len == strlen(name) && memcmp(entry->name, name, entry->name_len) == 0) {
                *found_inode = entry->inode;
                *file_type = entry->file_type;
                result = 0;
                goto cleanup;
            }

            ptr += entry->rec_len;
        }
        remaining_size -= (remaining_size < block_size) ? remaining_size : block_size;
    }

    cleanup:
        fs_xfree(block_buffer);
    return result;
}

static int copy_file_content(int img, struct fs_inode *inode, uint32_t block_size, int out) {
    char *block_buffer = fs_xmalloc(block_size);
    uint64_t remaining_size = inode->size_lower;
    off_t write_offset = 0;
    int result = 0;

    // Direct blocks
    for (int i = 0; i < 12 && inode->direct_block_pointers[i] && remaining_size > 0; i++) {
        result = read_block(img, block_buffer, inode->direct_block_pointers[i], block_size);
        if (result < 0) break;

        uint32_t to_write = (remaining_size < block_size) ? remaining_size : block_size;
        result = write_data(out, block_buffer, to_write, write_offset);
        if (result < 0) break;

        remaining_size -= to_write;
        write_offset += to_write;
    }

    if (result == 0 && inode->singly_indirect_block && remaining_size > 0) {
        uint32_t *indirect_block = fs_xmalloc(block_size);
        result = read_block(img, indirect_block, inode->singly_indirect_block, block_size);

        if (result == 0) {
            for (uint32_t i = 0; i < block_size/4 && indirect_block[i] && remaining_size > 0; i++) {
                result = read_block(img, block_buffer, indirect_block[i], block_size);
                if (result < 0) break;

                uint32_t to_write = (remaining_size < block_size) ? remaining_size : block_size;
                result = write_data(out, block_buffer, to_write, write_offset);
                if (result < 0) break;

                remaining_size -= to_write;
                write_offset += to_write;
            }
        }
        fs_xfree(indirect_block);
    }

    fs_xfree(block_buffer);
    return result;
}

int dump_file(int img, const char *path, int out) {
    struct fs_superblock *sb = fs_xmalloc(sizeof(struct fs_superblock));
    if (pread(img, sb, sizeof(struct fs_superblock), 1024) != sizeof(struct fs_superblock)) {
        fs_xfree(sb);
        return -EIO;
    }

    uint32_t block_size = 1024 << sb->s_log_block_size_kbytes;
    int current_inode_num = 2;  // Start from root
    const char *p = path;
    if (*p == '/') p++;

    struct fs_inode *current_inode = fs_xmalloc(sizeof(struct fs_inode));
    int result = 0;

    while (*p && result == 0) {
        // Read current inode
        uint32_t block_group = (current_inode_num - 1) / sb->s_inodes_per_group;
        uint32_t local_inode = (current_inode_num - 1) % sb->s_inodes_per_group;
        uint8_t group_desc[32];

        result = pread(img, group_desc, sizeof(group_desc),
                      2048 + (block_group * 32)) != sizeof(group_desc) ? -EIO : 0;

        if (result == 0) {
            uint32_t inode_table_block = *(uint32_t*)(&group_desc[8]);
            uint32_t inode_offset = (inode_table_block * block_size) +
                                  (local_inode * sb->s_inode_size);

            result = pread(img, current_inode, sizeof(struct fs_inode), inode_offset) !=
                    sizeof(struct fs_inode) ? -EIO : 0;
        }

        if (result < 0) break;

        // Get next path component
        const char *next_slash = strchr(p, '/');
        size_t component_len = next_slash ? (size_t)(next_slash - p) : strlen(p);
        char *component = fs_xmalloc(component_len + 1);
        memcpy(component, p, component_len);
        component[component_len] = '\0';

        // Find in current directory
        int found_inode;
        uint8_t file_type;
        result = find_file_in_dir(img, block_size, current_inode, component, &found_inode, &file_type);

        if (result == 0) {
            if (!next_slash && file_type != EXT2_FT_REG_FILE) {
                result = -EISDIR;
            } else if (next_slash && file_type != EXT2_FT_DIR) {
                result = -ENOTDIR;
            } else {
                current_inode_num = found_inode;
                p = next_slash ? next_slash + 1 : p + component_len;
            }
        }

        fs_xfree(component);
    }

    if (result == 0) {
        // Read final inode
        uint32_t block_group = (current_inode_num - 1) / sb->s_inodes_per_group;
        uint32_t local_inode = (current_inode_num - 1) % sb->s_inodes_per_group;
        uint8_t group_desc[32];

        if (pread(img, group_desc, sizeof(group_desc), 2048 + (block_group * 32)) == sizeof(group_desc)) {
            uint32_t inode_table_block = *(uint32_t*)(&group_desc[8]);
            uint32_t inode_offset = (inode_table_block * block_size) +
                                  (local_inode * sb->s_inode_size);

            if (pread(img, current_inode, sizeof(struct fs_inode), inode_offset) == sizeof(struct fs_inode)) {
                result = copy_file_content(img, current_inode, block_size, out);
            } else {
                result = -EIO;
            }
        } else {
            result = -EIO;
        }
    }

    fs_xfree(current_inode);
    fs_xfree(sb);
    return result;
}
