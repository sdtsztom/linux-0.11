/*
 *  linux/kernel/hd.c
 *
 *  (C) 1991  Linus Torvalds
 */

/*
 * This is the low-level hd interrupt support. It traverses the
 * request-list, using interrupts to jump between functions. As
 * all the functions are called within interrupts, we may not
 * sleep. Special care is recommended.
 * 
 *  modified by Drew Eckhardt to check nr of hd's from the CMOS.
 */

#include <linux/config.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/hdreg.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/segment.h>

#define MAJOR_NR 3
#include "blk.h"

#define CMOS_READ(addr) ({ \
outb_p(0x80|addr,0x70); \
inb_p(0x71); \
})

/* Max read/write errors/sector */
#define MAX_ERRORS	7
#define MAX_HD		2

static void recal_intr(void);

static int recalibrate = 1;
static int reset = 1;

/*
 *  This struct defines the HD's and their types.
 */
struct hd_i_struct {	// tsz: #personal 物理硬盘的物理信息
	int head,sect,cyl,wpcom,lzone,ctl;
	};
#ifdef HD_TYPE
struct hd_i_struct hd_info[] = { HD_TYPE };
#define NR_HD ((sizeof (hd_info))/(sizeof (struct hd_i_struct)))
#else
struct hd_i_struct hd_info[] = { {0,0,0,0,0,0},{0,0,0,0,0,0} };
static int NR_HD = 0;
#endif

static struct hd_struct {	// tsz: #personal 每个逻辑硬盘的扇区信息，5是每个硬盘最大的逻辑分区数
	long start_sect;
	long nr_sects;
} hd[5*MAX_HD]={{0,0},};

#define port_read(port,buf,nr) \
__asm__("cld;rep;insw"::"d" (port),"D" (buf),"c" (nr))

#define port_write(port,buf,nr) \
__asm__("cld;rep;outsw"::"d" (port),"S" (buf),"c" (nr))

extern void hd_interrupt(void);
extern void rd_load(void);

/* This may be used only once, enforced by 'static int callable' */
int sys_setup(void * BIOS)
{
	static int callable = 1;
	int i,drive;
	unsigned char cmos_disks;
	struct partition *p;
	struct buffer_head * bh;

	if (!callable)	// tsz: #book 控制只调用一次
		return -1;
	callable = 0;
#ifndef HD_TYPE
	for (drive=0 ; drive<2 ; drive++) {	// tsz: #book2 以下部分注释来自内核完全注释
		hd_info[drive].cyl = *(unsigned short *) BIOS;			// 柱面数	// tsz: #personal 结构类型是hd_i_struct
		hd_info[drive].head = *(unsigned char *) (2+BIOS);		// 磁头数
		hd_info[drive].wpcom = *(unsigned short *) (5+BIOS);	// 写前预补偿柱面号
		hd_info[drive].ctl = *(unsigned char *) (8+BIOS);		// 控制字节
		hd_info[drive].lzone = *(unsigned short *) (12+BIOS);	// 磁头着陆区柱面号
		hd_info[drive].sect = *(unsigned char *) (14+BIOS);		// 每磁道扇区数
		BIOS += 16;	// 每个硬盘的参数表长16直接，这里BIOS指向下一个表
	}
	if (hd_info[1].cyl)	// tsz: #book 判断有几块硬盘
		NR_HD=2;	// 磁盘数置为2
	else
		NR_HD=1;
#endif
// tsz: #book 一个物理硬盘最多可以分为4个逻辑盘，0是物理盘，1~4是逻辑盘，共5个，第1个物理盘是0*5，第2个物理盘是1*5
	for (i=0 ; i<NR_HD ; i++) {
		hd[i*5].start_sect = 0;	// tsz: #personal 结构类型是hd_struct，现在都只有一个逻辑盘，所以都只设置每个物理硬盘的第一个逻辑硬盘
		hd[i*5].nr_sects = hd_info[i].head*
				hd_info[i].sect*hd_info[i].cyl;	// tsz: #personal 磁道数*柱面数*每柱面扇区数为总共的扇区数
	}

	/*
		We querry CMOS about hard disks : it could be that 
		we have a SCSI/ESDI/etc controller that is BIOS
		compatable with ST-506, and thus showing up in our
		BIOS table, but not register compatable, and therefore
		not present in CMOS.

		Furthurmore, we will assume that our ST-506 drives
		<if any> are the primary drives in the system, and 
		the ones reflected as drive 1 or 2.

		The first drive is stored in the high nibble of CMOS
		byte 0x12, the second in the low nibble.  This will be
		either a 4 bit drive type or 0xf indicating use byte 0x19 
		for an 8 bit type, drive 1, 0x1a for drive 2 in CMOS.

		Needless to say, a non-zero value means we have 
		an AT controller hard disk for that drive.

		
	*/

	if ((cmos_disks = CMOS_READ(0x12)) & 0xf0)
		if (cmos_disks & 0x0f)
			NR_HD = 2;
		else
			NR_HD = 1;
	else
		NR_HD = 0;
	for (i = NR_HD ; i < 2 ; i++) {
		hd[i*5].start_sect = 0;
		hd[i*5].nr_sects = 0;
	}
	// tsz: #book 第1个个物理盘设备号是0x300，第2个是0x305，读每个物理硬盘的0号块，即引导块（注意这个系统中一个块为两个扇区），有分区信息
	for (drive=0 ; drive<NR_HD ; drive++) {
		if (!(bh = bread(0x300 + drive*5,0))) {	// tsz: #course 300的含义其实是将第9位设置成硬盘的设备号3，在这里传入设备号后在ll_rw_block()中取出设备号并找到对应的blk_dev
			printk("Unable to read partition table of drive %d\n\r",
				drive);
			panic("");
		}
		if (bh->b_data[510] != 0x55 || (unsigned char)	// tsz: #book 硬盘信息有效位标志
		    bh->b_data[511] != 0xAA) {
			printk("Bad partition table on drive %d\n\r",drive);
			panic("");
		}
		p = 0x1BE + (void *)bh->b_data;	// tsz: #book 根据引导块中的信息设置hd[]
		for (i=1;i<5;i++,p++) {
			hd[i+5*drive].start_sect = p->start_sect;
			hd[i+5*drive].nr_sects = p->nr_sects;
		}
		brelse(bh);	// tsz: #book 引用数-1
	}
	if (NR_HD)
		printk("Partition table%s ok.\n\r",(NR_HD>1)?"s":"");
	rd_load();
	mount_root();
	return (0);
}

static int controller_ready(void)
{
	int retries=10000;

	while (--retries && (inb_p(HD_STATUS)&0xc0)!=0x40);
	return (retries);
}

static int win_result(void)
{
	int i=inb_p(HD_STATUS);

	if ((i & (BUSY_STAT | READY_STAT | WRERR_STAT | SEEK_STAT | ERR_STAT))
		== (READY_STAT | SEEK_STAT))
		return(0); /* ok */
	if (i&1) i=inb(HD_ERROR);
	return (1);
}

static void hd_out(unsigned int drive,unsigned int nsect,unsigned int sect,
		unsigned int head,unsigned int cyl,unsigned int cmd,
		void (*intr_addr)(void))
{
	register int port asm("dx");

	if (drive>1 || head>15)
		panic("Trying to write bad sector");
	if (!controller_ready())
		panic("HD controller not ready");
	do_hd = intr_addr;	// tsz: #course 挂钩子;现代操作系统要让中断处理函数尽可能短，开一个线程去处理，这样可以让中断尽可能多地进来
	outb_p(hd_info[drive].ctl,HD_CMD);
	port=HD_DATA;
	outb_p(hd_info[drive].wpcom>>2,++port);
	outb_p(nsect,++port);
	outb_p(sect,++port);
	outb_p(cyl,++port);
	outb_p(cyl>>8,++port);
	outb_p(0xA0|(drive<<4)|head,++port);
	outb(cmd,++port);	// tsz: #course 这里控制读写
}

static int drive_busy(void)
{
	unsigned int i;

	for (i = 0; i < 10000; i++)
		if (READY_STAT == (inb_p(HD_STATUS) & (BUSY_STAT|READY_STAT)))
			break;
	i = inb(HD_STATUS);
	i &= BUSY_STAT | READY_STAT | SEEK_STAT;
	if (i == (READY_STAT | SEEK_STAT))
		return(0);
	printk("HD controller times out\n\r");
	return(1);
}

static void reset_controller(void)
{
	int	i;

	outb(4,HD_CMD);
	for(i = 0; i < 100; i++) nop();
	outb(hd_info[0].ctl & 0x0f ,HD_CMD);
	if (drive_busy())
		printk("HD-controller still busy\n\r");
	if ((i = inb(HD_ERROR)) != 1)
		printk("HD-controller reset failed: %02x\n\r",i);
}

static void reset_hd(int nr)
{
	reset_controller();
	hd_out(nr,hd_info[nr].sect,hd_info[nr].sect,hd_info[nr].head-1,
		hd_info[nr].cyl,WIN_SPECIFY,&recal_intr);
}

void unexpected_hd_interrupt(void)
{
	printk("Unexpected HD interrupt\n\r");
}

static void bad_rw_intr(void)
{
	if (++CURRENT->errors >= MAX_ERRORS)
		end_request(0);
	if (CURRENT->errors > MAX_ERRORS/2)
		reset = 1;
}

static void read_intr(void)
{
	if (win_result()) {
		bad_rw_intr();
		do_hd_request();
		return;
	}
	port_read(HD_DATA,CURRENT->buffer,256);	// tsz: #personal 将输入读到bh指向的的buffer里，256是代表256字，即512字节
	CURRENT->errors = 0;
	CURRENT->buffer += 512;
	CURRENT->sector++;
	if (--CURRENT->nr_sectors) {	// tsz: #personal 若还有扇区没读
		do_hd = &read_intr;	// tsz: #personal 继续挂载中断函数;#ques 中断函数在每次操作完会被清除?
		return;
	}
	end_request(1);	// tsz: #course 这个参数决定了uptodate的值
	do_hd_request();	// tsz: #course #note #impo #desi #universal 造成循环去处理，这是通过中断去不断执行;#personal 不依赖于任何进程;注意这个循环不是永久的，前提是有请求项在，即只要还有请求项，就一直循环
}

static void write_intr(void)
{
	if (win_result()) {
		bad_rw_intr();
		do_hd_request();
		return;
	}
	if (--CURRENT->nr_sectors) {
		CURRENT->sector++;
		CURRENT->buffer += 512;
		do_hd = &write_intr;
		port_write(HD_DATA,CURRENT->buffer,256);
		return;
	}
	end_request(1);
	do_hd_request();
}

static void recal_intr(void)
{
	if (win_result())
		bad_rw_intr();
	do_hd_request();
}

void do_hd_request(void)
{
	int i,r = 0;
	unsigned int block,dev;
	unsigned int sec,head,cyl;
	unsigned int nsect;

	INIT_REQUEST;	// tsz: #personal 检查正确性
	dev = MINOR(CURRENT->dev);	// tsz: #course CURRENT为当前请求项，定义在blk.h;注意CURRENT不依靠调用，可以被循环执行
	block = CURRENT->sector;
	if (dev >= 5*NR_HD || block+2 > hd[dev].nr_sects) {
		end_request(0);
		goto repeat;	// 该标号在blk.h最后面	// tsz: #personal 如果没有待处理的request了;#impo 在这里进行返回;并且处理的循环终止了
	}
	block += hd[dev].start_sect;
	dev /= 5;
	__asm__("divl %4":"=a" (block),"=d" (sec):"0" (block),"1" (0),
		"r" (hd_info[dev].sect));
	__asm__("divl %4":"=a" (cyl),"=d" (head):"0" (block),"1" (0),
		"r" (hd_info[dev].head));
	sec++;
	nsect = CURRENT->nr_sectors;
	if (reset) {
		reset = 0;
		recalibrate = 1;	// tsz: #personal calibrate：校准
		reset_hd(CURRENT_DEV);	// tsz: #book 将通过调用hd_out向硬盘发送WIN_SPECIFY命令，建立读盘必要参数
		return;
	}
	if (recalibrate) {
		recalibrate = 0;
		hd_out(dev,hd_info[CURRENT_DEV].sect,0,0,0,	// tsz: #book 向硬盘发送WIN_RESTORE命令，将磁头移动到0柱面，以便从硬盘上读取数据
			WIN_RESTORE,&recal_intr);
		return;
	}	
	if (CURRENT->cmd == WRITE) {
		hd_out(dev,nsect,sec,head,cyl,WIN_WRITE,&write_intr);	// tsz: #course 写中断，（中断的)钩子，对照下面的READ的调用，可以发现读写的过程就是钩子有区别（文件读写的代码大部分一致-90%，就在这分叉）
		for(i=0 ; i<3000 && !(r=inb_p(HD_STATUS)&DRQ_STAT) ; i++)
			/* nothing */ ;
		if (!r) {
			bad_rw_intr();
			goto repeat;
		}
		port_write(HD_DATA,CURRENT->buffer,256);
	} else if (CURRENT->cmd == READ) {
		hd_out(dev,nsect,sec,head,cyl,WIN_READ,&read_intr);
	} else
		panic("unknown hd-command");
}

// 硬盘系统初始化
// 设置硬盘中断描述符，并允许硬盘控制器发送中断请求信号。
// 该函数设置硬盘设备的请求项处理函数指针为do_hd_request(),然后设置硬盘中断门
// 描述符。Hd_interrupt(kernel/system_call.s)是其中断处理过程。硬盘中断号为
// int 0x2E(46),对应8259A芯片的中断请求信号IRQ13.接着复位接联的主8250A int2
// 的屏蔽位，允许从片发出中断请求信号。再复位硬盘的中断请求屏蔽位(在从片上)，
// 允许硬盘控制器发送中断信号。中断描述符表IDT内中断门描述符设置宏set_intr_gate().
void hd_init(void)
{
	blk_dev[MAJOR_NR].request_fn = DEVICE_REQUEST;      // do_hd_request()	// tsz: #personal 编号为3;#note #impo 这个是对所有请求的处理函数，即上面的do_hd_request()
	set_intr_gate(0x2E,&hd_interrupt);	// tsz: #personal 中断函数在system_call.s中
	outb_p(inb_p(0x21)&0xfb,0x21);                      // 复位接联的主8259A int2的屏蔽位
	outb(inb_p(0xA1)&0xbf,0xA1);                        // 复位硬盘中断请求屏蔽位(在从片上)
}
