/*
 * ext2ck.c
 * reads a filesystem image (name specified as command-line arg), analyze the
 * image and produce a CSV summary; then spawns a Python script to analyze the
 * summary and check for corruption
 *
 * Ian Brault <ianbrault@ucla.edu>
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ext2.h"

/* offset of superblock */
#define SUPER_OFFSET 1024

/* file formats */
const __u16 EXT2_S_IFREG = 0x8000;
const __u16 EXT2_S_IFDIR = 0x4000;
const __u16 EXT2_S_IFLNK = 0xA000;

/* count the # of bits set in a bitmap */
#define BITMAP_COUNT(bmp) __builtin_popcount(bmp)

void *Malloc(size_t size);
ssize_t Pread(int fd, void *buf, size_t count, off_t offset);

void parse_args(int argc, char *argv[]);

/* stat EXT2 info, store in structs */
int ext2_read_super(struct ext2_super_block *esb, off_t offset);
int ext2_read_group_desc(struct ext2_group_desc *egd, off_t offset);
int ext2_read_inode(struct ext2_inode *ei, off_t offset);
int ext2_read_dirent(struct ext2_dir_entry *ede, char *dir_blocks,
					 off_t offset, int size);

/* print CSV logs for various structs */
void ext2_super_csv(const struct ext2_super_block esb);
void ext2_group_csv(const struct ext2_group_desc egd, int gn);
void ext2_group_scan_bitmaps(const struct ext2_group_desc egd);
void ext2_inode_csv(struct ext2_inode ei, int in);
void ext2_dir_csv(struct ext2_inode dir_inode, int in);
void ext2_indir_block_csv(const struct ext2_inode ei, int inode_num);
void ext2_indir_block_csv_helper(int inode, int indir, int offset, int block);

/* filesystem image file descriptor */
static int imgfd = -1;

/* disk structure variables, set after reading superblock */
static int BLOCK_SIZE = 0;
static int INODE_SIZE = 0;
static int BLOCKS_PER_GROUP = 0;
static int INODES_PER_GROUP = 0;
static int GROUP_SIZE = 0;
static int N_GROUPS = 0;


/* malloc wrapper */
void *
Malloc(size_t size)
{
	void *b = malloc(size);
	if (!b) { perror("malloc"); _exit(1); }
	return b;
}


/* pread wrapper */
ssize_t
Pread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t r = pread(fd, buf, count, offset);
	if (r < 0) { perror("pread"); _exit(1); }
	return r;
}


/* parse command-line args */
void
parse_args(int argc, char *argv[])
{
	const char usage[] = "ext2ck fs_img";
  
	// should have 1 arg, name of filesystem image
	if (argc != 2)
    {
		fprintf(stderr, "error: invalid arguments\nusage: %s\n", usage);
		_exit(1);
    }

	imgfd = open(argv[1], O_RDONLY);
	if (imgfd < 0)
    {
		perror("open failed");
		_exit(2);
    }
}


/*
 * get info about the EXT2 superblock at the specified offset, 
 * storing the info into the ext2_super_block struct
 * @param esb : where the info will be stored
 * @param offset : the start of the superblock
 * @return 0 on success, -1 on failure
 */
int
ext2_read_super(struct ext2_super_block *esb, off_t offset)
{
	char *buf;  
	// allocate buffer to block size
	buf = Malloc(EXT2_MIN_BLOCK_SIZE * sizeof(char));
	// read superblock into buffer
	Pread(imgfd, buf, EXT2_MIN_BLOCK_SIZE, offset);
	
	// reference for superblock structure & offsets:
	// www.nongnu.org/ext2-doc/ext2.html#SUPERBLOCK
	
	memcpy(&esb->s_inodes_count, &buf[0], 4);
	memcpy(&esb->s_blocks_count, &buf[4], 4);
	memcpy(&esb->s_r_blocks_count, &buf[8], 4);
	memcpy(&esb->s_free_blocks_count, &buf[12], 4);
	memcpy(&esb->s_free_inodes_count, &buf[16], 4);
	memcpy(&esb->s_first_data_block, &buf[20], 4);
	memcpy(&esb->s_log_block_size, &buf[24], 4);
	memcpy(&esb->s_log_frag_size,  &buf[28], 4);
	memcpy(&esb->s_blocks_per_group, &buf[32], 4);
	memcpy(&esb->s_frags_per_group,  &buf[36], 4);
	memcpy(&esb->s_inodes_per_group, &buf[40], 4);
	
	memcpy(&esb->s_first_ino, &buf[84], 4);
	memcpy(&esb->s_inode_size, &buf[88], 4);
	memcpy(&esb->s_block_group_nr, &buf[90], 4);
	
	free(buf);
	return 0;
}


/*
 * get info about the EXT2 group descriptor at the specified offset, 
 * storing the info into the ext2_group_desc struct
 * @param egd : where the info will be stored
 * @param offset : the start of the block group descriptor table
 * @return 0 on success, -1 on failure
 */
int
ext2_read_group_desc(struct ext2_group_desc *egd, off_t offset)
{
	char *buf;
	// allocate buffer to block size
	buf = Malloc(BLOCK_SIZE * sizeof(char));
	// read group table into buffer
	Pread(imgfd, buf, BLOCK_SIZE, offset);
	
	// reference for superblock structure & offsets:
	// www.nongnu.org/ext2-doc/ext2.html#BLOCK-GROUP-DESCRIPTOR-TABLE
	
	memcpy(&egd->bg_block_bitmap, &buf[0], 4);
	memcpy(&egd->bg_inode_bitmap, &buf[4], 4);
	memcpy(&egd->bg_inode_table,  &buf[8], 4);
	memcpy(&egd->bg_free_blocks_count, &buf[12], 2);
	memcpy(&egd->bg_free_inodes_count, &buf[14], 2);
	memcpy(&egd->bg_used_dirs_count, &buf[16], 2);
	
	free(buf);
	return 0;
}


/*
 * get info about the EXT2 inode at the specified offset, 
 * storing the info into the ext2_inode struct
 * @param ei : where the info will be stored
 * @param offset : the start of the inode
 * @return 0 on success, -1 on failure
 */
int
ext2_read_inode(struct ext2_inode *ei, off_t offset)
{
	int i;
	char *buf;
  
	// allocate buffer to block size
	buf = Malloc(BLOCK_SIZE * sizeof(char));
	// read inode block into buffer
	Pread(imgfd, buf, BLOCK_SIZE, offset);
  
	// reference for superblock structure & offsets:
	// www.nongnu.org/ext2-doc/ext2.html#INODE-TABLE

	memcpy(&ei->i_mode, &buf[0], 2);
	memcpy(&ei->i_uid,  &buf[2], 2);
	memcpy(&ei->i_size,  &buf[4], 4);
	memcpy(&ei->i_atime, &buf[8], 4);
	memcpy(&ei->i_ctime, &buf[12], 4);
	memcpy(&ei->i_mtime, &buf[16], 4);
	memcpy(&ei->i_gid, &buf[24], 2);
	memcpy(&ei->i_links_count, &buf[26], 2);
	memcpy(&ei->i_blocks, &buf[28], 4);
	
	// read in inode blocks
	for (i = 0; i < EXT2_N_BLOCKS; i++)
	{
		memcpy(&ei->i_block[i], &buf[40 + 4*i], 4);
	}
  
	free(buf);
	return 0;
}


/*
 * get info about the EXT2 directory entry at the specified offset, 
 * storing the info into the ext2_dir_entry struct
 * @param ede : where the info will be stored
 * @param dir_blocks : a byte array of every data block in the directory
 * @param offset : offset of the start of the directory entry into dir_blocks
 * @param size : size of the directory entry
 * @return 0 on success, -1 on failure
 */
int
ext2_read_dirent(struct ext2_dir_entry *ede, char *dir_blocks,
		 off_t offset, int size)
{
	char *buf;
	// allocate buffer to size of dirent
	buf = Malloc(size * sizeof(char));
	// read dirent into buffer
	memcpy(buf, &dir_blocks[offset], size);

	// reference for superblock structure & offsets:
	// www.nongnu.org/ext2-doc/ext2.html#DIRECTORY
  
	memcpy(&ede->inode, &buf[0], 4);
	memcpy(&ede->rec_len, &buf[4], 2);
	memcpy(&ede->name_len, &buf[6], 1);
	memcpy(&ede->file_type, &buf[7], 1);
	memcpy(&ede->name, &buf[8], ede->name_len);
	
	free(buf);
	return 0;
}


/*
 * print a comma-separated (CSV) record for the provided structure
 * @param esb : contains the info to be printed
 */
void
ext2_super_csv(struct ext2_super_block esb)
{
	int bsize = EXT2_MIN_BLOCK_SIZE << esb.s_log_block_size;
	printf("SUPERBLOCK,%d,%d,%d,%d,%d,%d,%d\n",
		   esb.s_blocks_count, esb.s_inodes_count, bsize, esb.s_inode_size,
		   esb.s_blocks_per_group, esb.s_inodes_per_group, esb.s_first_ino);
}


/*
 * print a comma-separated (CSV) record for the provided strucure
 * @param egd : contains the info to be printed
 * @param gn : group number
 */
void
ext2_group_csv(struct ext2_group_desc egd, int gn)
{
	printf("GROUP,%d,%d,%d,%d,%d,%d,%d,%d\n",
		   gn, BLOCKS_PER_GROUP, INODES_PER_GROUP, egd.bg_free_blocks_count,
		   egd.bg_free_inodes_count, egd.bg_block_bitmap, egd.bg_inode_bitmap,
		   egd.bg_inode_table);
}


/*
 * scan the block group's free block and free inode bitmaps
 * for each free block/inode, produce a brief CSV
 * @param egd : block group descriptor table info structure
 */
void
ext2_group_scan_bitmaps(struct ext2_group_desc egd)
{
	int i, j, n_blocks, in;
	int block_bmp, inode_bmp, inode_table;
	char *buf, *chunk;

	// keep track of which inodes are allocated
	int *used_inodes;
	
	struct ext2_inode inode;
	int offset;
	
	n_blocks = BLOCKS_PER_GROUP;
	block_bmp = egd.bg_block_bitmap;
	inode_bmp = egd.bg_inode_bitmap;
	inode_table = egd.bg_inode_table;

	buf = Malloc(BLOCK_SIZE * sizeof(char));
	chunk = Malloc(sizeof(char));
	used_inodes = Malloc((INODES_PER_GROUP+1) * sizeof(int));

	// read block bitmap into buffer
	Pread(imgfd, buf, BLOCK_SIZE, block_bmp * BLOCK_SIZE);

	// scan byte-at-a-time
	for (i = 0; i < n_blocks; i++)
    {
		chunk = memcpy(chunk, &buf[i], 1);
		// go through chunk
		for (j = 0; j < 8; j++)
		{
			if (!(((*chunk) >> j) & 1)) printf("BFREE,%d\n", 8*i + j + 1);
		}
    }

	// read inode bitmap into buffer
	Pread(imgfd, buf, BLOCK_SIZE, inode_bmp * BLOCK_SIZE);
	// scan byte-at-a-time
	for (i = 0; i < INODES_PER_GROUP/8; i++)
    {
		chunk = memcpy(chunk, &buf[i], 1);
		// go through chunk
		for (j = 0; j < 8; j++)
		{
			in = 8*i + j + 1;
			// if free, log as free inode
			if (!(((*chunk) >> j) & 1))
			{
				printf("IFREE,%d\n", in);
				used_inodes[in-1] = 0;
			}
			// otherwise, keep track that it's allocated
			else used_inodes[in-1] = 1;
		}
    }

	// get allocated inodes
	for (i = 0; i < INODES_PER_GROUP; i++)
    {
		// if allocated...
		if (used_inodes[i])
		{
			in = i + 1;
			offset = (inode_table * BLOCK_SIZE) + ((in-1) * INODE_SIZE);
			ext2_read_inode(&inode, offset);
			// if valid (non-zero mode, non-zero link count) print CSV summary
			if (inode.i_mode != 0 && inode.i_links_count != 0)
			{
				ext2_inode_csv(inode, in);
				// if directory, print its entries
				if ((inode.i_mode & 0xF000) == EXT2_S_IFDIR)
					ext2_dir_csv(inode, in);
				ext2_indir_block_csv(inode, in);
			}
		}
    }

	free(used_inodes);
	free(chunk);
	free(buf);
}


/*
 * produce a CSV summary for an inode
 * @param ei : inode structure holding the relevant info
 * @param in : inode number
 */
void
ext2_inode_csv(struct ext2_inode ei, int in)
{
	int i;
	__u16 mode;
	char type, ctime[18], mtime[18], atime[18];
	time_t ct, mt, at;
	struct tm *tm_c, *tm_m, *tm_a;

	// determine file type
	mode = ei.i_mode & 0xF000;
	if (mode == EXT2_S_IFREG) type = 'f';
	else if (mode == EXT2_S_IFDIR) type = 'd';
	else if (mode == EXT2_S_IFLNK) type = 's';
	else type = '?';
	
	// get time string for creation time
	ct = ei.i_ctime;
	tm_c = gmtime(&ct);
	if (!tm_c) { perror("gmtime failed"); _exit(1); }
	// correct to make year 2 digits
	if (tm_c->tm_year >= 100) tm_c->tm_year -= 100;
	// NOTE: months are 1 less than they need to be
	snprintf(ctime, 18, "%02d/%02d/%02d %02d:%02d:%02d",
			 tm_c->tm_mon+1, tm_c->tm_mday, tm_c->tm_year,
			 tm_c->tm_hour, tm_c->tm_min, tm_c->tm_sec);
	
	// get time string for modification time
	mt = ei.i_mtime;
	tm_m = gmtime(&mt);
	if (!tm_m) { perror("gmtime failed"); _exit(1); }
	// correct to make year 2 digits
	if (tm_m->tm_year >= 100) tm_m->tm_year -= 100;
	// NOTE: months are 1 less than they need to be
	snprintf(mtime, 18, "%02d/%02d/%02d %02d:%02d:%02d",
			 tm_m->tm_mon+1, tm_m->tm_mday, tm_m->tm_year,
			 tm_m->tm_hour, tm_m->tm_min, tm_m->tm_sec);

	// get time string for access time
	at = ei.i_atime;
	tm_a = gmtime(&at);
	if (!tm_a) { perror("gmtime failed"); _exit(1); }
	// correct to make year 2 digits
	if (tm_a->tm_year >= 100) tm_a->tm_year -= 100;
	// NOTE: months are 1 less than they need to be
	snprintf(atime, 18, "%02d/%02d/%02d %02d:%02d:%02d",
			 tm_a->tm_mon+1, tm_a->tm_mday, tm_a->tm_year,
			 tm_a->tm_hour, tm_a->tm_min, tm_a->tm_sec);
	
	// print inode attributes
	printf("INODE,%d,%c,%o,%d,%d,%d,%s,%s,%s,%d,%d",
		   in, type, ei.i_mode & 0x0FFF, ei.i_uid, ei.i_gid, ei.i_links_count,
		   ctime, mtime, atime, ei.i_size, ei.i_blocks);
	// print block addresses
	for (i = 0; i < 15; i++) printf(",%d", ei.i_block[i]);
	printf("\n");
}


/*
 * produce a CSV summary for a directory
 * @param dir_inode : contains info about the directory inode
 * @param in : the inode number of the directory
 */
void
ext2_dir_csv(struct ext2_inode dir_inode, int in)
{
	int i;
	char *buf, *name;
	struct ext2_dir_entry dirent;
	int dir_size, dirent_offset;
	__u16 dirent_size;
	
	int *indir_block;

	// note: i_blocks is in units of 512 bytes
	dir_size = dir_inode.i_blocks * 512;
  
	buf = Malloc(dir_size * sizeof(char));
	name = Malloc(255 * sizeof(char));
	
	// read in direct blocks to buffer
	i = 0;
	while (dir_inode.i_block[i] != 0 && i < 12)
    {
		Pread(imgfd, &buf[i*BLOCK_SIZE], BLOCK_SIZE, dir_inode.i_block[i]*BLOCK_SIZE);
		i++;
    }

	// if > 12 blocks, read in from indirect blocks
	if (dir_size/BLOCK_SIZE > 12)
    {
		// allocate and read in indirect block
		indir_block = Malloc(BLOCK_SIZE);
		Pread(imgfd, indir_block, BLOCK_SIZE, dir_inode.i_block[12] * BLOCK_SIZE);
		
		// read in indirect blocks
		i = 0;
		while (indir_block[i] != 0)
		{
			Pread(imgfd, &buf[(i+12)*BLOCK_SIZE], BLOCK_SIZE,
				  indir_block[i] * BLOCK_SIZE);
			i++;
		}
		
		free(indir_block);
    }
	
	// read in first directory entry
	dirent_offset = 0;
	memcpy(&dirent_size, &buf[4], 2);
	ext2_read_dirent(&dirent, buf, dirent_offset, dirent_size);
	
	// log subsequent entries
	while (dirent.inode != 0 && dirent_offset < dir_size)
    {
		memcpy(name, &dirent.name, dirent.name_len);
		name[dirent.name_len] = 0;
		printf("DIRENT,%d,%d,%d,%d,%d,'%s'\n",
			   in, dirent_offset, dirent.inode, dirent.rec_len,
			   dirent.name_len, name);
		
		// read in next entry
		dirent_offset += dirent.rec_len;
		memcpy(&dirent_size, &buf[dirent_offset+4], 2);
		ext2_read_dirent(&dirent, buf, dirent_offset, dirent_size);
      
		if (dirent.rec_len == 0) break;
    }

	free(name);
	free(buf);
}


/*
 * print a CSV summary for an inode indirect block
 * @param ei : contains info about the inode
 * @param inode_num : respective inode number
 */
void
ext2_indir_block_csv(const struct ext2_inode ei, int inode_num)
{
	int next_block_1, next_block_2, next_block_3;
	// get block numbers for all indirect blocks 
	next_block_1 = ei.i_block[12];
	next_block_2 = ei.i_block[13];
	next_block_3 = ei.i_block[14];
	
	if (next_block_1 != 0)
	{
		ext2_indir_block_csv_helper(inode_num, 1, 12, next_block_1);
	}
	if (next_block_2 != 0)
	{
		ext2_indir_block_csv_helper(inode_num, 2, 268, next_block_2);
	}
	if (next_block_3 != 0)
	{
		ext2_indir_block_csv_helper(inode_num, 3, 65804, next_block_3);
	}
}


/*
 * recursive helper function for ext2_indir_block_csv
 * @param inode : inode number for respective inode
 * @param indir : current level of indirection
 * @param offset : file offset of the current block
 * @param block : block number of the current block
 */
void
ext2_indir_block_csv_helper(int inode, int indir, int offset, int block)
{
	int i = 0;
	int refblock = 0;
	int *buf;

	// allocate buffer to block size
	buf = Malloc(BLOCK_SIZE * sizeof(int));
	// read into buffer
	Pread(imgfd, buf, BLOCK_SIZE, block*BLOCK_SIZE);
	
	refblock = buf[0];
	while (refblock != 0 && i != 256)
    {
		printf("INDIRECT,%d,%d,%d,%d,%d\n",
			   inode, indir, offset, block, refblock);
		if (indir == 1) offset++;
		else if (indir == 2)
		{
			offset += 256;
			ext2_indir_block_csv_helper(inode, 1, offset, refblock);
		}
		else if (indir == 3)
		{
			offset += 65536;
			ext2_indir_block_csv_helper(inode, 2, offset, refblock );
		}
      
		i++;
		refblock = buf[i];
    }
  
	free(buf);
}


int
main(int argc, char *argv[])
{
	int i;
	struct ext2_super_block super;
	struct ext2_group_desc *groups;
  
	// parse command-line args
	parse_args(argc, argv);

	// get info about superblock & print CSV
	ext2_read_super(&super, SUPER_OFFSET);
	ext2_super_csv(super);

	// record disk statistics
	BLOCK_SIZE = EXT2_MIN_BLOCK_SIZE << super.s_log_block_size;
	INODE_SIZE = super.s_inode_size;
	N_GROUPS = (super.s_blocks_count-1)/super.s_blocks_per_group + 1;
	BLOCKS_PER_GROUP = super.s_blocks_count / N_GROUPS;
	INODES_PER_GROUP = super.s_inodes_count / N_GROUPS;
	GROUP_SIZE = BLOCKS_PER_GROUP * BLOCK_SIZE;

	// get info about block group descriptor tables
	// located in 1st block following superblock
	groups = Malloc(N_GROUPS * sizeof(struct ext2_group_desc));
	for (i = 0; i < N_GROUPS; i++)
    {
		ext2_read_group_desc(&groups[i], GROUP_SIZE*i + SUPER_OFFSET+BLOCK_SIZE);
		ext2_group_csv(groups[i], i);
    }
	// scan group bitmaps for free blocks/inodes
	for (i = 0; i < N_GROUPS; i++) ext2_group_scan_bitmaps(groups[i]);

	free(groups);
	return 0;
}
