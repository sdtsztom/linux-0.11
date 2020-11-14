/*
 * This file has definitions for some important file table
 * structures etc.
 */

#ifndef _FS_H
#define _FS_H

#include <sys/types.h>

/* devices are as follows: (same as minix, so we can use the minix
 * file system. These are major numbers.)
 *
 * 0 - unused (nodev)
 * 1 - /dev/mem
 * 2 - /dev/fd
 * 3 - /dev/hd
 * 4 - /dev/ttyx
 * 5 - /dev/tty
 * 6 - /dev/lp
 * 7 - unnamed pipes
 */

#define IS_SEEKABLE(x) ((x)>=1 && (x)<=3)

#define READ 0
#define WRITE 1
#define READA 2		/* read-ahead - don't pause */
#define WRITEA 3	/* "write-ahead" - silly, but somewhat useful */

void buffer_init(long buffer_end);

#define MAJOR(a) (((unsigned)(a))>>8)	// tsz: #personal b_dev是short，16bit
#define MINOR(a) ((a)&0xff)

#define NAME_LEN 14
#define ROOT_INO 1

#define I_MAP_SLOTS 8
#define Z_MAP_SLOTS 8
#define SUPER_MAGIC 0x137F

#define NR_OPEN 20
#define NR_INODE 32
#define NR_FILE 64
#define NR_SUPER 8
#define NR_HASH 307
#define NR_BUFFERS nr_buffers
#define BLOCK_SIZE 1024
#define BLOCK_SIZE_BITS 10
#ifndef NULL
#define NULL ((void *) 0)
#endif

#define INODES_PER_BLOCK ((BLOCK_SIZE)/(sizeof (struct d_inode)))
#define DIR_ENTRIES_PER_BLOCK ((BLOCK_SIZE)/(sizeof (struct dir_entry)))

#define PIPE_HEAD(inode) ((inode).i_zone[0])
#define PIPE_TAIL(inode) ((inode).i_zone[1])
#define PIPE_SIZE(inode) ((PIPE_HEAD(inode)-PIPE_TAIL(inode))&(PAGE_SIZE-1))
#define PIPE_EMPTY(inode) (PIPE_HEAD(inode)==PIPE_TAIL(inode))
#define PIPE_FULL(inode) (PIPE_SIZE(inode)==(PAGE_SIZE-1))
#define INC_PIPE(head) \
__asm__("incl %0\n\tandl $4095,%0"::"m" (head))

typedef char buffer_block[BLOCK_SIZE];

struct buffer_head {	// tsz: #personal 34B;下面的注释来自赵炯的书
	char * b_data;			/* pointer to data block (1024 bytes) */	//指针
	unsigned long b_blocknr;	/* block number */	//块号
	unsigned short b_dev;		/* device (0 = free) */	//数据源的设备号
	unsigned char b_uptodate;	//更新标志：表示数据是否已经更新	// tsz: #course #think b_uptodate的作用;#answ 根本目的是为了数据一致性;不能理解为等价
	unsigned char b_dirt;		/* 0-clean,1-dirty */	
	unsigned char b_count;		/* users using this block */
	unsigned char b_lock;		/* 0 - ok, 1 -locked */
	struct task_struct * b_wait;
	struct buffer_head * b_prev;
	struct buffer_head * b_next;
	struct buffer_head * b_prev_free;
	struct buffer_head * b_next_free;
};

struct d_inode {
	unsigned short i_mode;
	unsigned short i_uid;
	unsigned long i_size;
	unsigned long i_time;
	unsigned char i_gid;
	unsigned char i_nlinks;
	unsigned short i_zone[9];
};

struct m_inode {
	unsigned short i_mode;			// 文件类型和属性(rwx 位)
	unsigned short i_uid;			// 用户 id（文件拥有者标识符）
	unsigned long i_size;			// 文件大小（字节数）
	unsigned long i_mtime;			// 修改时间（自 1970.1.1:0 算起，秒）
	unsigned char i_gid;			// 组 id(文件拥有者所在的组)
	unsigned char i_nlinks;			// 文件目录项链接数
	unsigned short i_zone[9];		// 直接(0-6)、间接(7)或双重间接(8)逻辑块号
/* these are in memory also */
	struct task_struct * i_wait;	// 等待该 i 节点的进程
	unsigned long i_atime;			// 最后访问时间
	unsigned long i_ctime;			// i 节点自身修改时间
	unsigned short i_dev;			// i 节点所在的设备号
	unsigned short i_num;			// i 节点号
	unsigned short i_count;			// i 节点被使用的次数，0 表示该 i 节点空闲
	unsigned char i_lock;			// 锁定标志
	unsigned char i_dirt;			// 已修改(脏)标志
	unsigned char i_pipe;			// 管道标志
	unsigned char i_mount;			// 安装标志
	unsigned char i_seek;			// 搜寻标志(lseek 时)
	unsigned char i_update;			// 更新标志
};

struct file {
	unsigned short f_mode;
	unsigned short f_flags;
	unsigned short f_count;
	struct m_inode * f_inode;
	off_t f_pos;
};

struct super_block {
	unsigned short s_ninodes;		// 节点数
	unsigned short s_nzones;		// 逻辑块数
	unsigned short s_imap_blocks;	// i节点位图所占的数据块数
	unsigned short s_zmap_blocks;	// 逻辑块位图所占用的数据块数
	unsigned short s_firstdatazone;	// 第一个数据逻辑块号
	unsigned short s_log_zone_size;	// log(数据块数/逻辑块)。(以2为底)
	unsigned long s_max_size;		// 文件最大长度
	unsigned short s_magic;			// 文件系统魔数
/* These are only in memory */
	struct buffer_head * s_imap[8];	// i节点位图缓冲块指针数组（占用8块，可表示64M）
	struct buffer_head * s_zmap[8];	// 逻辑块位图缓冲块指针数组（占用 8 块）
	unsigned short s_dev;			// 超级块所在的设备号
	struct m_inode * s_isup;		// 被安装的文件系统根目录的 i 节点
	struct m_inode * s_imount;		// 被安装到的 i 节点
	unsigned long s_time;			// 修改时间
	struct task_struct * s_wait;	// 等待该超级块的进程
	unsigned char s_lock;			// 被锁定标志
	unsigned char s_rd_only;		// 只读标志
	unsigned char s_dirt;			// 已修改(脏)标志
};

struct d_super_block {	// tsz: #personal 硬盘中存储的超级块
	unsigned short s_ninodes;
	unsigned short s_nzones;
	unsigned short s_imap_blocks;
	unsigned short s_zmap_blocks;
	unsigned short s_firstdatazone;
	unsigned short s_log_zone_size;
	unsigned long s_max_size;
	unsigned short s_magic;
};

struct dir_entry {
	unsigned short inode;
	char name[NAME_LEN];
};

extern struct m_inode inode_table[NR_INODE];
extern struct file file_table[NR_FILE];
extern struct super_block super_block[NR_SUPER];
extern struct buffer_head * start_buffer;
extern int nr_buffers;

extern void check_disk_change(int dev);
extern int floppy_change(unsigned int nr);
extern int ticks_to_floppy_on(unsigned int dev);
extern void floppy_on(unsigned int dev);
extern void floppy_off(unsigned int dev);
extern void truncate(struct m_inode * inode);
extern void sync_inodes(void);
extern void wait_on(struct m_inode * inode);
extern int bmap(struct m_inode * inode,int block);
extern int create_block(struct m_inode * inode,int block);
extern struct m_inode * namei(const char * pathname);
extern int open_namei(const char * pathname, int flag, int mode,
	struct m_inode ** res_inode);
extern void iput(struct m_inode * inode);
extern struct m_inode * iget(int dev,int nr);
extern struct m_inode * get_empty_inode(void);
extern struct m_inode * get_pipe_inode(void);
extern struct buffer_head * get_hash_table(int dev, int block);
extern struct buffer_head * getblk(int dev, int block);
extern void ll_rw_block(int rw, struct buffer_head * bh);
extern void brelse(struct buffer_head * buf);
extern struct buffer_head * bread(int dev,int block);
extern void bread_page(unsigned long addr,int dev,int b[4]);
extern struct buffer_head * breada(int dev,int block,...);
extern int new_block(int dev);
extern void free_block(int dev, int block);
extern struct m_inode * new_inode(int dev);
extern void free_inode(struct m_inode * inode);
extern int sync_dev(int dev);
extern struct super_block * get_super(int dev);
extern int ROOT_DEV;

extern void mount_root(void);

#endif
