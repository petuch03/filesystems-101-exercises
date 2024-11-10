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

struct ext2_fs
{
	int fd;
	struct ext2_super_block sb;
	struct ext2_group_desc *gd;
	uint32_t block_size;
	uint32_t groups_count;
};

struct ext2_blkiter
{
	struct ext2_fs *fs;
	struct ext2_inode inode;
	uint32_t curr_block;
	uint32_t total_blocks;
	int indirect_level;
	uint32_t *indirect_blocks;
	uint32_t indirect_pos[4];
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
	new_fs->groups_count = (new_fs->sb.s_blocks_count - 1) / new_fs->sb.s_blocks_per_group + 1;

	// Read group descriptors
	size_t gd_size = sizeof(struct ext2_group_desc) * new_fs->groups_count;
	new_fs->gd = fs_xmalloc(gd_size);

	off_t gd_offset = new_fs->block_size;
	if (new_fs->block_size > 1024)
		gd_offset = new_fs->block_size * 2;

	bytes = pread(fd, new_fs->gd, gd_size, gd_offset);
	if ((unsigned long) bytes != gd_size) {
		fs_xfree(new_fs->gd);
		fs_xfree(new_fs);
		return -EIO;
	}

	*fs = new_fs;
	return 0;
}

void ext2_fs_free(struct ext2_fs *fs)
{
	if (fs) {
		close(fs->fd);
		fs_xfree(fs->gd);
		fs_xfree(fs);
	}
}

static int read_inode(struct ext2_fs *fs, int ino, struct ext2_inode *inode) {
	if (ino < 1 || (unsigned int) ino > fs->sb.s_inodes_count)
		return -EINVAL;

	uint32_t group = (ino - 1) / fs->sb.s_inodes_per_group;
	uint32_t index = (ino - 1) % fs->sb.s_inodes_per_group;

	off_t offset = fs->gd[group].bg_inode_table * fs->block_size +
				   index * sizeof(struct ext2_inode);

	ssize_t bytes = pread(fs->fd, inode, sizeof(struct ext2_inode), offset);
	return bytes == sizeof(struct ext2_inode) ? 0 : -EIO;
}

int ext2_blkiter_init(struct ext2_blkiter **i, struct ext2_fs *fs, int ino)
{
	struct ext2_blkiter *iter = fs_xzalloc(sizeof(struct ext2_blkiter));
	iter->fs = fs;

	int ret = read_inode(fs, ino, &iter->inode);
	if (ret < 0) {
		fs_xfree(iter);
		return ret;
	}

	if (iter->inode.i_links_count == 0) {
		fs_xfree(iter);
		return -ENOENT;
	}

	iter->curr_block = 0;
	iter->total_blocks = iter->inode.i_blocks / (2 << (fs->sb.s_log_block_size));
	iter->indirect_blocks = NULL;

	*i = iter;
	return 0;
}

static int read_block(struct ext2_fs *fs, uint32_t block_no, void *buffer) {
	off_t offset = block_no * fs->block_size;
	ssize_t bytes = pread(fs->fd, buffer, fs->block_size, offset);
	return bytes == fs->block_size ? 0 : -EIO;
}

static int get_indirect_block(struct ext2_blkiter *i, uint32_t block_no, uint32_t *result) {
	if (!i->indirect_blocks)
		i->indirect_blocks = fs_xmalloc(i->fs->block_size);

	int ret = read_block(i->fs, block_no, i->indirect_blocks);
	if (ret < 0)
		return ret;

	*result = i->indirect_blocks[i->indirect_pos[i->indirect_level]];
	return 0;
}

int ext2_blkiter_next(struct ext2_blkiter *i, int *blkno)
{
	if (i->curr_block >= i->total_blocks)
		return 0;

	uint32_t block = i->curr_block;
	uint32_t result;

	if (block < 12) {
		result = i->inode.i_block[block];
	} else {
		block -= 12;
		uint32_t addr_per_block = i->fs->block_size / 4;

		if (block < addr_per_block) {
			i->indirect_level = 1;
			i->indirect_pos[1] = block;
			if (get_indirect_block(i, i->inode.i_block[12], &result) < 0)
				return -EPROTO;
		} else if (block < addr_per_block * addr_per_block) {
			block -= addr_per_block;
			i->indirect_level = 2;
			i->indirect_pos[1] = block / addr_per_block;
			i->indirect_pos[2] = block % addr_per_block;

			uint32_t indirect_block;
			if (get_indirect_block(i, i->inode.i_block[13], &indirect_block) < 0)
				return -EPROTO;
			if (get_indirect_block(i, indirect_block, &result) < 0)
				return -EPROTO;
		} else {
			block -= addr_per_block * addr_per_block;
			i->indirect_level = 3;
			i->indirect_pos[1] = block / (addr_per_block * addr_per_block);
			i->indirect_pos[2] = (block / addr_per_block) % addr_per_block;
			i->indirect_pos[3] = block % addr_per_block;

			uint32_t indirect_block1, indirect_block2;
			if (get_indirect_block(i, i->inode.i_block[14], &indirect_block1) < 0)
				return -EPROTO;
			if (get_indirect_block(i, indirect_block1, &indirect_block2) < 0)
				return -EPROTO;
			if (get_indirect_block(i, indirect_block2, &result) < 0)
				return -EPROTO;
		}
	}

	if (result >= i->fs->sb.s_blocks_count)
		return -EPROTO;

	*blkno = result;
	i->curr_block++;
	return 1;
}

void ext2_blkiter_free(struct ext2_blkiter *i)
{
	if (i) {
		if (i->indirect_blocks)
			fs_xfree(i->indirect_blocks);
		fs_xfree(i);
	}
}
