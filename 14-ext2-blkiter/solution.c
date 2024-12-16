#include <solution.h>
#include <fs_malloc.h>

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#define EXT2_SUPER_MAGIC    0xEF53
#define EXT2_VALID_FS       0x0001
#define EXT2_BLOCK_SIZE_MIN 1024

struct ext2_super_block {
	uint32_t s_inodes_count;
	uint32_t s_blocks_count;
	uint32_t s_r_blocks_count;
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
	uint16_t s_def_resuid;
	uint16_t s_def_resgid;
	uint16_t s_inode_size;
} __attribute__((packed));

struct ext2_group_desc {
	uint32_t bg_block_bitmap;
	uint32_t bg_inode_bitmap;
	uint32_t bg_inode_table;
	uint16_t bg_free_blocks_count;
	uint16_t bg_free_inodes_count;
	uint16_t bg_used_dirs_count;
	uint16_t bg_pad;
	uint32_t bg_reserved[3];
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
	uint32_t i_osd1;
	uint32_t i_block[15];
	uint32_t i_generation;
	uint32_t i_file_acl;
	uint32_t i_dir_acl;
	uint32_t i_faddr;
	uint32_t i_osd2[3];
} __attribute__((packed));

struct ext2_fs {
	int fd;
	int block_size;
	struct ext2_super_block sb;
};

struct ext2_blkiter {
	struct ext2_fs *fs;
	int inode_table;

	struct ext2_inode inode;
	int current;

	int *indirect_block;
	int *double_indirect_block;
	int current_indirect_block_num;
};

int ext2_fs_init(struct ext2_fs **fs, int fd) {
    struct ext2_fs *fs_temp = fs_xmalloc(sizeof(struct ext2_fs));
    fs_temp->fd = fd;

    ssize_t bytes = pread(fd, &fs_temp->sb, sizeof(struct ext2_super_block), 1024);
    if (bytes != sizeof(struct ext2_super_block)) {
        fs_xfree(fs_temp);
        return -EIO;
    }

    if (fs_temp->sb.s_magic != EXT2_SUPER_MAGIC) {
        fs_xfree(fs_temp);
        return -EPROTO;
    }

    fs_temp->block_size = EXT2_BLOCK_SIZE_MIN << fs_temp->sb.s_log_block_size;
    *fs = fs_temp;
    return 0;
}

int ext2_blkiter_init(struct ext2_blkiter **i, struct ext2_fs *fs, int ino) {
    size_t desc_per_block = fs->block_size / sizeof(struct ext2_group_desc);
    size_t group_index = (ino - 1) / fs->sb.s_inodes_per_group;
    size_t inode_index = (ino - 1) % fs->sb.s_inodes_per_group;

    size_t desc_block = fs->sb.s_first_data_block + 1 + group_index / desc_per_block;
    size_t desc_offset = (group_index % desc_per_block) * sizeof(struct ext2_group_desc);

    struct ext2_group_desc group_desc;
    ssize_t read_bytes = pread(fs->fd, &group_desc, sizeof(group_desc),
                              fs->block_size * desc_block + desc_offset);
    if (read_bytes != sizeof(group_desc)) {
        return -EIO;
    }

    struct ext2_blkiter *iter = fs_xmalloc(sizeof(struct ext2_blkiter));
    iter->inode_table = group_desc.bg_inode_table;

    read_bytes = pread(fs->fd, &iter->inode, sizeof(struct ext2_inode),
                      fs->block_size * iter->inode_table + inode_index * fs->sb.s_inode_size);
    if (read_bytes != sizeof(struct ext2_inode)) {
        fs_xfree(iter);
        return -EIO;
    }

    iter->current = 0;
    iter->fs = fs;
    iter->indirect_block = NULL;
    iter->double_indirect_block = NULL;
    iter->current_indirect_block_num = -1;

    *i = iter;
    return 0;
}

int ext2_blkiter_next(struct ext2_blkiter *i, int *blkno) {
    int ptrs_per_block = i->fs->block_size / sizeof(int);

    int direct_end = 12;  // EXT2_NDIR_BLOCKS
    int indirect_start = direct_end;
    int indirect_end = direct_end + ptrs_per_block;
    int double_indirect_start = indirect_end;
    int double_indirect_end = indirect_end + ptrs_per_block * ptrs_per_block;

    // Direct blocks
    if (i->current < direct_end) {
        int ptr = i->inode.i_block[i->current];
        if (ptr == 0) {
            return 0;
        }
        *blkno = ptr;
        i->current++;
        return 1;
    }

    // Single indirect blocks
    if (i->current < indirect_end) {
        if (!i->indirect_block) {
            i->indirect_block = fs_xmalloc(i->fs->block_size);
            if (pread(i->fs->fd, i->indirect_block, i->fs->block_size,
                     i->inode.i_block[12] * i->fs->block_size) == -1) {
                return -errno;
            }
        }

        if (i->indirect_block[i->current - indirect_start] == 0) {
            return 0;
        }

        *blkno = i->indirect_block[i->current - indirect_start];
        i->current++;
        return 1;
    }

    // Double indirect blocks
    if (i->current < double_indirect_end) {
        if (!i->double_indirect_block) {
            i->double_indirect_block = fs_xmalloc(i->fs->block_size);
            if (pread(i->fs->fd, i->double_indirect_block, i->fs->block_size,
                     i->inode.i_block[13] * i->fs->block_size) == -1) {
                return -errno;
            }
        }

        int indirect_idx = (i->current - double_indirect_start) / ptrs_per_block;
        int direct_idx = (i->current - double_indirect_start) % ptrs_per_block;

        if (!i->indirect_block) {
            i->indirect_block = fs_xmalloc(i->fs->block_size);
        }

        if (i->current_indirect_block_num != i->double_indirect_block[indirect_idx]) {
            i->current_indirect_block_num = i->double_indirect_block[indirect_idx];
            if (pread(i->fs->fd, i->indirect_block, i->fs->block_size,
                     i->current_indirect_block_num * i->fs->block_size) == -1) {
                return -errno;
            }
        }

        if (i->indirect_block[direct_idx] == 0) {
            return 0;
        }

        *blkno = i->indirect_block[direct_idx];
        i->current++;
        return 1;
    }

    return 0;
}

void ext2_blkiter_free(struct ext2_blkiter *i) {
    if (i) {
        fs_xfree(i->indirect_block);
        fs_xfree(i->double_indirect_block);
        fs_xfree(i);
    }
}