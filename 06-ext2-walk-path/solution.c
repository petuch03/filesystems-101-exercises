#include <solution.h>

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
        ssize_t written = pwrite(fd, buf + total_written,
                               size - total_written,
                               offset + total_written);
        if (written < 0) return -errno;
        total_written += written;
    }
    return 0;
}

static int read_inode(int img, struct fs_superblock *sb, int inode_nr, struct fs_inode *inode) {
    uint32_t block_size = 1024 << sb->s_log_block_size_kbytes;
    uint32_t block_group = (inode_nr - 1) / sb->s_inodes_per_group;
    uint32_t local_inode = (inode_nr - 1) % sb->s_inodes_per_group;
    uint32_t group_desc_size = 32;
    uint32_t group_desc_offset = BLOCK_GROUP_DESC_OFFSET + (block_group * group_desc_size);

    uint8_t group_desc[32];
    if (pread(img, group_desc, sizeof(group_desc), group_desc_offset) != sizeof(group_desc))
        return -EIO;

    uint32_t inode_table_block = *(uint32_t*)(&group_desc[8]);
    uint32_t inode_offset = (inode_table_block * block_size) + (local_inode * sb->s_inode_size);

    if (pread(img, inode, sizeof(struct fs_inode), inode_offset) != sizeof(struct fs_inode))
        return -EIO;

    return 0;
}

static int find_file_in_dir(int img, struct fs_superblock *sb, struct fs_inode *dir_inode,
                           const char *name, int *found_inode) {
    uint32_t block_size = 1024 << sb->s_log_block_size_kbytes;
    char *block_buffer = fs_xmalloc(block_size);
    int result = 0;
    uint64_t remaining_size = dir_inode->size_lower;

    // Check direct blocks
    for (int i = 0; i < POINTERS && dir_inode->direct_block_pointers[i] && remaining_size > 0; i++) {
        result = read_block(img, block_buffer, dir_inode->direct_block_pointers[i], block_size);
        if (result < 0) goto cleanup;

        char *ptr = block_buffer;
        while (ptr < block_buffer + block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)ptr;
            if (entry->inode == 0 || entry->rec_len == 0) break;

            if (entry->name_len == strlen(name) &&
                memcmp(entry->name, name, entry->name_len) == 0) {
                *found_inode = entry->inode;
                result = (entry->file_type == EXT2_FT_REG_FILE) ? 1 :
                        (entry->file_type == EXT2_FT_DIR) ? 2 : 0;
                goto cleanup;
            }

            ptr += entry->rec_len;
        }
        remaining_size -= (remaining_size < block_size) ? remaining_size : block_size;
    }

    // Not found
    result = -ENOENT;

cleanup:
    fs_xfree(block_buffer);
    return result;
}

int dump_file(int img, const char *path, int out) {
    struct fs_superblock *sb = fs_xmalloc(sizeof(struct fs_superblock));
    struct fs_inode *inode = fs_xmalloc(sizeof(struct fs_inode));
    int result = 0;

    // Read superblock
    if (pread(img, sb, sizeof(*sb), SUPERBLOCK_OFFSET) != sizeof(*sb)) {
        result = -EIO;
        goto cleanup_init;
    }
    if (sb->s_magic != EXT2_SUPER_MAGIC) {
        result = -EINVAL;
        goto cleanup_init;
    }

    // Start from root inode
    int current_inode = 2;  // Root directory inode
    const char *p = path;

    // Skip leading slash
    if (*p == '/') p++;

    // Parse path components
    while (*p) {
        // Read current directory inode
        result = read_inode(img, sb, current_inode, inode);
        if (result < 0) goto cleanup_init;

        // Extract next path component
        const char *next_slash = strchr(p, '/');
        size_t component_len = next_slash ? (size_t)(next_slash - p) : strlen(p);
        char *component = fs_xmalloc(component_len + 1);
        memcpy(component, p, component_len);
        component[component_len] = '\0';

        // Find component in current directory
        int found_inode;
        result = find_file_in_dir(img, sb, inode, component, &found_inode);
        fs_xfree(component);

        if (result < 0) goto cleanup_init;  // Not found
        if (!next_slash && result != 1) {   // Last component must be a regular file
            result = -EISDIR;
            goto cleanup_init;
        }
        if (next_slash && result != 2) {    // Intermediate components must be directories
            result = -ENOTDIR;
            goto cleanup_init;
        }

        current_inode = found_inode;
        p = next_slash ? next_slash + 1 : p + component_len;
    }

    // Read the final file inode
    result = read_inode(img, sb, current_inode, inode);
    if (result < 0) goto cleanup_init;

    // Now copy the file contents using the same logic as in previous task
    uint32_t block_size = 1024 << sb->s_log_block_size_kbytes;
    char *block_buffer = fs_xmalloc(block_size);
    uint64_t remaining_size = inode->size_lower;
    off_t write_offset = 0;

    // Process direct blocks
    for (int i = 0; i < POINTERS && inode->direct_block_pointers[i] && remaining_size > 0; i++) {
        result = read_block(img, block_buffer, inode->direct_block_pointers[i], block_size);
        if (result < 0) goto cleanup;

        uint32_t to_write = (remaining_size < block_size) ? remaining_size : block_size;
        result = write_data(out, block_buffer, to_write, write_offset);
        if (result < 0) goto cleanup;

        remaining_size -= to_write;
        write_offset += to_write;
    }

    // Process single indirect block if needed
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

cleanup:
    fs_xfree(block_buffer);
cleanup_init:
    fs_xfree(inode);
    fs_xfree(sb);
    return result;
}
