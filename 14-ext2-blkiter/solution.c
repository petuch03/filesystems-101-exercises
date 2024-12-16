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
    struct ext2_super_block sb;
    uint32_t block_size;
};

struct ext2_blkiter {
    struct ext2_fs *fs;
    struct ext2_inode inode;
    int current;
    uint32_t *direct_ptr;
    uint32_t *indirect_ptr;
    uint32_t direct_blocks;
    uint32_t indirect_blocks;
};

int ext2_fs_init(struct ext2_fs **fs, int fd) {
	struct ext2_fs *new_fs = fs_xzalloc(sizeof(struct ext2_fs));
	new_fs->fd = fd;

	ssize_t bytes = pread(fd, &new_fs->sb, sizeof(struct ext2_super_block), 1024);
	if (bytes != sizeof(struct ext2_super_block)) {
		fs_xfree(new_fs);
		return -EIO;
	}

	if (new_fs->sb.s_magic != EXT2_SUPER_MAGIC) {
		fs_xfree(new_fs);
		return -EPROTO;
	}

    new_fs->block_size = EXT2_BLOCK_SIZE_MIN << new_fs->sb.s_log_block_size;
    *fs = new_fs;
    return 0;
}

void ext2_fs_free(struct ext2_fs *fs)
{
	if (fs) {
		close(fs->fd);
		fs_xfree(fs);
	}
}

static int read_block(struct ext2_fs *fs, uint32_t block_no, void *buffer) {
	off_t offset = block_no * fs->block_size;
	ssize_t bytes = pread(fs->fd, buffer, fs->block_size, offset);
	return bytes == fs->block_size ? 0 : -EIO;
}

int ext2_blkiter_init(struct ext2_blkiter **i, struct ext2_fs *fs, int ino) {
    if (ino < 1) {
        return -EINVAL;
    }

    struct ext2_blkiter *iter = fs_xzalloc(sizeof(struct ext2_blkiter));
    iter->fs = fs;

    int inode_index = (ino - 1) % fs->sb.s_inodes_per_group;
    int group_index = (ino - 1) / fs->sb.s_inodes_per_group;

    struct ext2_group_desc group_desc;
    int desc_per_block = fs->block_size / sizeof(struct ext2_group_desc);
    int desc_block = fs->sb.s_first_data_block + 1 + group_index / desc_per_block;
    int desc_offset = (group_index % desc_per_block) * sizeof(struct ext2_group_desc);

    ssize_t read_bytes = pread(fs->fd, &group_desc, sizeof(group_desc),
                              desc_block * fs->block_size + desc_offset);
    if (read_bytes != sizeof(group_desc)) {
        fs_xfree(iter);
        return -EIO;
    }

    read_bytes = pread(fs->fd, &iter->inode, sizeof(struct ext2_inode),
                      group_desc.bg_inode_table * fs->block_size +
                      inode_index * 128);  // Standard inode size in ext2
    if (read_bytes != sizeof(struct ext2_inode)) {
        fs_xfree(iter);
        return -EIO;
    }

    if (iter->inode.i_mode == 0) {
        fs_xfree(iter);
        return -ENOENT;
    }

    iter->current = 0;
    iter->direct_ptr = NULL;
    iter->indirect_ptr = NULL;
    iter->direct_blocks = 0;
    iter->indirect_blocks = 0;

    *i = iter;
    return 0;
}

int ext2_blkiter_next(struct ext2_blkiter *i, int *blkno) {
    uint32_t ptrs_per_block = i->fs->block_size / sizeof(uint32_t);

    // Direct blocks
    if (i->current < 12) {
        if (i->inode.i_block[i->current] == 0) {
            return 0;
        }
        *blkno = i->inode.i_block[i->current];
        i->current++;
        return 1;
    }

    // Single indirect blocks
    if ((uint32_t)i->current < (12 + ptrs_per_block)) {
        // First access to indirect block
        if (!i->direct_ptr) {
            if (i->inode.i_block[12] == 0) {
                return 0;
            }
            i->direct_ptr = fs_xmalloc(i->fs->block_size);
            if (read_block(i->fs, i->inode.i_block[12], i->direct_ptr) < 0) {
                return -EIO;
            }
            *blkno = i->inode.i_block[12];
            i->direct_blocks = i->inode.i_block[12];
            return 1;
        }

        // Return pointers from indirect block
        int indirect_index = i->current - 12;
        if (i->direct_ptr[indirect_index] == 0) {
            i->current++;
            return ext2_blkiter_next(i, blkno);
        }
        *blkno = i->direct_ptr[indirect_index];
        i->current++;
        return 1;
    }

    // Double indirect blocks
    if ((uint32_t)i->current < (12 + ptrs_per_block + ptrs_per_block * ptrs_per_block)) {
        // First access to double indirect block
        if (!i->indirect_ptr) {
            if (i->inode.i_block[13] == 0) {
                return 0;
            }
            i->indirect_ptr = fs_xmalloc(i->fs->block_size);
            if (read_block(i->fs, i->inode.i_block[13], i->indirect_ptr) < 0) {
                return -EIO;
            }
            *blkno = i->inode.i_block[13];
            i->indirect_blocks = i->inode.i_block[13];
            return 1;
        }

        uint32_t double_offset = i->current - (12 + ptrs_per_block);
        uint32_t indirect_index = double_offset / ptrs_per_block;
        uint32_t direct_index = double_offset % ptrs_per_block;

        // Load new indirect block from double indirect
        if (direct_index == 0) {
            if (i->indirect_ptr[indirect_index] == 0) {
                i->current = (i->current + ptrs_per_block - 1) / ptrs_per_block * ptrs_per_block;
                i->current++;
                return ext2_blkiter_next(i, blkno);
            }
            if (!i->direct_ptr) {
                i->direct_ptr = fs_xmalloc(i->fs->block_size);
            }
            if (read_block(i->fs, i->indirect_ptr[indirect_index], i->direct_ptr) < 0) {
                return -EIO;
            }
            *blkno = i->indirect_ptr[indirect_index];
            i->direct_blocks = i->indirect_ptr[indirect_index];
            return 1;
        }

        if (i->direct_ptr[direct_index] == 0) {
            i->current++;
            return ext2_blkiter_next(i, blkno);
        }
        *blkno = i->direct_ptr[direct_index];
        i->current++;
        return 1;
    }

    return 0;
}


void ext2_blkiter_free(struct ext2_blkiter *i) {
    if (i) {
        fs_xfree(i->direct_ptr);
        fs_xfree(i->indirect_ptr);
        fs_xfree(i);
    }
}
