/*
 *  linux/kernel/blk_dev/ll_rw.c
 *
 * (C) 1991 Linus Torvalds
 */

/*
 * This handles all read/write requests to block devices
 */
#include <errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <asm/system.h>

#include "blk.h"

/*
 * The request-struct contains all necessary data
 * to load a nr of sectors into memory
 */
struct request request[NR_REQUEST];

/*
 * used to wait on when there are no free requests
 */
struct task_struct * wait_for_request = NULL;

/* blk_dev_struct is:
 *	do_request-address
 *	next-request
 */
struct blk_dev_struct blk_dev[NR_BLK_DEV] = {
	{ NULL, NULL },		/* no_dev */
	{ NULL, NULL },		/* dev mem */
	{ NULL, NULL },		/* dev fd */
	{ NULL, NULL },		/* dev hd */
	{ NULL, NULL },		/* dev ttyx */
	{ NULL, NULL },		/* dev tty */
	{ NULL, NULL }		/* dev lp */
};

static inline void lock_buffer(struct buffer_head * bh)
{
	cli();
	while (bh->b_lock)
		sleep_on(&bh->b_wait);
	bh->b_lock=1;
	sti();
}

static inline void unlock_buffer(struct buffer_head * bh)
{
	if (!bh->b_lock)
		printk("ll_rw_block.c: buffer not locked\n\r");
	bh->b_lock = 0;
	wake_up(&bh->b_wait);
}

/*
 * add-request adds a request to the linked list.
 * It disables interrupts so that it can muck with the
 * request-lists in peace.
 */
// tsz: #personal #fsum 将请求项插入或直接执行 
static void add_request(struct blk_dev_struct * dev, struct request * req)
{
	struct request * tmp;

	req->next = NULL;
	cli();
	if (req->bh)
		req->bh->b_dirt = 0;	// tsz: #course 清脏位
	if (!(tmp = dev->current_request)) {
		dev->current_request = req;
		sti();
		(dev->request_fn)();	// tsz: #personal 执行处理函数
		return;
	}
	for ( ; tmp->next ; tmp=tmp->next)
		if ((IN_ORDER(tmp,req) || 	// tsz: #personal IN_ORDER是验证一定限制下前者的sect小于后者的sect;这里是给前两个判断条件(A||B)加了括号
		    !IN_ORDER(tmp,tmp->next)) &&
		    IN_ORDER(req,tmp->next))
			break;
	req->next=tmp->next;	// tsz: #personal #impo 最后的结果是按序插入
	tmp->next=req;
	sti();
}

// tsz: #personal #fusm 检查必要性，申请req，修改seq并开始调用add_request
static void make_request(int major,int rw, struct buffer_head * bh)
{
	struct request * req;
	int rw_ahead;

/* WRITEA/READA is special case - it is not really needed, so if the */
/* buffer is locked, we just forget about it, else it's a normal read */
	if ((rw_ahead = (rw == READA || rw == WRITEA))) {	// tsz: #course 这里的A后缀是预读的意思
		if (bh->b_lock)
			return;
		if (rw == READA)
			rw = READ;
		else
			rw = WRITE;
	}
	if (rw!=READ && rw!=WRITE)
		panic("Bad block dev command, must be R/W/RA/WA");
	lock_buffer(bh);	// tsz: #personal #impo 注意和wait_on_buffer的区别：后者得到buffer无锁，可以被其他进程使用
	if ((rw == WRITE && !bh->b_dirt) || (rw == READ && bh->b_uptodate)) {	// tsz: #course 检查操作必要性：不脏不用写，一致了不用读，出现这种没有的事情就直接不响应请求，直接解锁并返回
		unlock_buffer(bh);
		return;
	}
repeat:
/* we don't allow the write-requests to fill up the queue completely:
 * we want some room for reads: they take precedence. The last third
 * of the requests are only for reads.
 */
	if (rw == READ)	// tsz: #personal req是开始寻找的位置;#univ 从后往前找
		req = request+NR_REQUEST;	// tsz: #course 因为读比写的概率高，而且读比写着急，所以从最后面开始寻找有空的request，写只从2/3开始寻找
	else
		req = request+((NR_REQUEST*2)/3);
/* find an empty request */
	while (--req >= request)
		if (req->dev<0)	// tsz: #course -1 if no request,0-6对应7种设备
			break;
/* if none found, sleep on new requests: check for rw_ahead */
	if (req < request) {
		if (rw_ahead) {	// tsz: #personal 说明预读写在碰过分配不到请求项时就放弃
			unlock_buffer(bh);
			return;
		}
		sleep_on(&wait_for_request);	// tsz: #personal wait_for_request为NULL，传入的是指向NULL的指针;#note #impo 这种sleep on在task_struct的内核栈中形成链表
		goto repeat;
	}
/* fill up the request-info, and add it to the queue */
	req->dev = bh->b_dev;
	req->cmd = rw;
	req->errors=0;
	req->sector = bh->b_blocknr<<1;
	req->nr_sectors = 2;	// tsz: #course 两个扇区一个块
	req->buffer = bh->b_data;	// tsz: #personal 这里和下面第二行完成了req和bh挂接
	req->waiting = NULL;
	req->bh = bh;
	req->next = NULL;
	add_request(major+blk_dev,req);	// tsz: #course 核心
}

// tsz: #personal #fsum 检查合法性
void ll_rw_block(int rw, struct buffer_head * bh)
{
	unsigned int major;	// tsz: #book2 主设备号，硬盘主设备号是3

	if ((major=MAJOR(bh->b_dev)) >= NR_BLK_DEV ||	// tsz: #course 判断是不是设备
	!(blk_dev[major].request_fn)) {	// tsz: #course 判断是否挂载了请求函数
		printk("Trying to read nonexistent block-device\n\r");
		return;
	}
	make_request(major,rw,bh);	// tsz: #personal 将块传递进去;#course bread中创建来的是READ类型
}

// 块设备初始化函数，由初始化程序main.c调用
// 初始化请求数组，将所有请求项置为空闲（dev = -1）,有32项（NR_REQUEST = 32）
void blk_dev_init(void)
{
	int i;

	for (i=0 ; i<NR_REQUEST ; i++) {
		request[i].dev = -1;	// tsz: #book #personal -1表示没有请求 request结构的定义在blk.h中
		request[i].next = NULL;	// tsz: #book 没有形成请求项队列
	}
}
