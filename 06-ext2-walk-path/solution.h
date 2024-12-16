#pragma once
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
