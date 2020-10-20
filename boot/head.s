/*
 *  linux/boot/head.s
 *
 *  (C) 1991  Linus Torvalds
 */

/*
 *  head.s contains the 32-bit startup code.
 *
 * NOTE!!! Startup happens at absolute address 0x00000000, which is also where
 * the page directory will exist. The startup code will be overwritten by
 * the page directory.
 */
.text
.globl idt,gdt,pg_dir,tmp_floppy_area
pg_dir:	# tsz: #book 标志内核分页机制完成后的内核起始位置
.globl startup_32
startup_32:
	movl $0x10,%eax	# tsz: #book 刚进入保护模式，第一次设置这些寄存器，这4个寄存器都指向内核数据段，0x10是gdt的第三项，即内核数据段
	mov %ax,%ds	# tsz: #course (#doubut对齐)
	mov %ax,%es
	mov %ax,%fs
	mov %ax,%gs
	lss stack_start,%esp	# tsz: #book #course stack_start(是两个数据的组合)，此时栈顶在user_stack的底端；定义在sched.c中，内核的栈，将来会变成用户栈(在system.h的move_to_user_mode中将特权变成了3特权)
		# tsz: #book #personal 还有对应的LDS、LES、LGS、LFS；lss应该其实也可以用上面的方法赋值，不过这里要要赋值ss和sp，一句顶两句
	call setup_idt
	call setup_gdt
	movl $0x10,%eax		# reload all the segment registers	# tsz: #book #personal #note 因为段限长的改变（在gdt项中），需要重新load，将对应的改变了的gtd项的值load进来
	mov %ax,%ds		# after changing gdt. CS was already
	mov %ax,%es		# reloaded in 'setup_gdt'
	mov %ax,%fs
	mov %ax,%gs
	lss stack_start,%esp
	xorl %eax,%eax
1:	incl %eax		# check that A20 really IS enabled 
	movl %eax,0x000000	# loop forever if it isn't
	cmpl %eax,0x100000
	je 1b	# tsz: #book 没打开则一直循环

/*
 * NOTE! 486 should set bit 16, to check for write-protect in supervisor
 * mode. Then it would be unnecessary with the "verify_area()"-calls.
 * 486 users probably want to set the NE (#5) bit also, so as to use
 * int 16 for math errors.
 */
 # tsz: #book 检查数学协处理器 
	movl %cr0,%eax		# check math chip
	andl $0x80000011,%eax	# Save PG,PE,ET
/* "orl $0x10020,%eax" here for 486 might be good */
	orl $2,%eax		# set MP
	movl %eax,%cr0
	call check_x87
	jmp after_page_tables	# tsz: #book 开始压栈main 

/*
 * We depend on ET to be correct. This checks for 287/387.
 */
check_x87:
	fninit
	fstsw %ax
	cmpb $0,%al
	je 1f			/* no coprocessor: have to set bits */
	movl %cr0,%eax
	xorl $6,%eax		/* reset MP, set EM */
	movl %eax,%cr0
	ret
.align 2
1:	.byte 0xDB,0xE4		/* fsetpm for 287, ignored by 387 */
	ret

/*
 *  setup_idt
 *
 *  sets up a idt with 256 entries pointing to
 *  ignore_int, interrupt gates. It then loads
 *  idt. Everything that wants to install itself
 *  in the idt-table may do so themselves. Interrupts
 *  are enabled elsewhere, when we can be relatively
 *  sure everything is ok. This routine will be over-
 *  written by the page tables.
 */
setup_idt:
	lea ignore_int,%edx	# tsz: #personal lea参考摘录，同时要注意edx、dx、dl、dh区别
		# tsz: #personal 可以看到后面对ignore_int的地址进行了复杂的拆分操作(可见书中图1-29)，这是因为要是IDT表项中的offset=ignore_int，而offset的位置分布在0、1、6、7B，所以下面要进行拆分
	movl $0x00080000,%eax	# tsz: #personal movl是mov32bit数据，movw是mov一个字，即2B
	movw %dx,%ax		/* selector = 0x0008 = cs */	# tsz: #book 段选择子是8 
	movw $0x8E00,%dx	/* interrupt gate - dpl=0, present */	# tsz: #book 这些位包含着很多信息(见书)，其中重要的是dpl=0(0特权)

	lea idt,%edi	# tsz #personal idt的flag在后面
	mov $256,%ecx
rp_sidt:	# tsz: #personal #note 还没有ret，所以程序还会继续往下执行 
	movl %eax,(%edi)	# tsz: #book eax、edx构建出一个完整的中断描述符(64bit)，然后将其写入idt位置中
	movl %edx,4(%edi)
	addl $8,%edi
	dec %ecx
	jne rp_sidt	# tsz: #personal 重复256此，填满256个表项
	lidt idt_descr # tsz: #personal 重新装载新的idt表描述符
	ret

/*
 *  setup_gdt
 *
 *  This routines sets up a new gdt and loads it.
 *  Only two entries are currently built, the same
 *  ones that were built in init.s. The routine
 *  is VERY complicated at two whole lines, so this
 *  rather long comment is certainly needed :-).
 *  This routine will beoverwritten by the page tables.
 */
setup_gdt:
	lgdt gdt_descr
	ret

/*
 * I put the kernel page tables right after the page directory,
 * using 4 of them to span 16 Mb of physical memory. People with
 * more than 16MB will have to expand this.
 */
.org 0x1000	# tsz: #course 页表
pg0:

.org 0x2000
pg1:

.org 0x3000
pg2:

.org 0x4000
pg3:

.org 0x5000
/*
 * tmp_floppy_area is used by the floppy-driver when DMA cannot
 * reach to a buffer-block. It needs to be aligned, so that it isn't
 * on a 64kB border.
 */
tmp_floppy_area:
	.fill 1024,1,0

after_page_tables:	# tsz: #course 手工压栈，相当于被main函数call了，那么ret之后就返回到main函数
	pushl $0		# These are the parameters to main :-)	# tsz: #book #personal 这些参数是envp、argv、argc；分别为环境变量、参数值，参数数(本来至少为1，是程序名)
	pushl $0
	pushl $0
	pushl $L6		# return address for main, if it decides to.	# tsz: #book 若main退出会跳到L6
	pushl $main	# tsz: #personal 这个地址应该到时候由编译器放入
	jmp setup_paging
L6:
	jmp L6			# main should never return here, but
				# just in case, we know what happens.

/* This is the default interrupt "handler" :-) */
int_msg:
	.asciz "Unknown interrupt\n\r"
.align 2
ignore_int:	# tsz: #personal 其内容为中断对应的操作 
	pushl %eax
	pushl %ecx
	pushl %edx
	push %ds
	push %es
	push %fs
	movl $0x10,%eax
	mov %ax,%ds
	mov %ax,%es
	mov %ax,%fs
	pushl $int_msg
	call printk
	popl %eax
	pop %fs
	pop %es
	pop %ds
	popl %edx
	popl %ecx
	popl %eax
	iret


/*
 * Setup_paging
 *
 * This routine sets up paging by setting the page bit
 * in cr0. The page tables are set up, identity-mapping
 * the first 16MB. The pager assumes that no illegal
 * addresses are produced (ie >4Mb on a 4Mb machine).
 *
 * NOTE! Although all physical memory should be identity
 * mapped by this routine, only the kernel page functions
 * use the >1Mb addresses directly. All "normal" functions
 * use just the lower 1Mb, or the local data space, which
 * will be mapped to some other place - mm keeps track of
 * that.
 *
 * For those with more memory than 16 Mb - tough luck. I've
 * not got it, why should you :-) The source is here. Change
 * it. (Seriously - it shouldn't be too difficult. Mostly
 * change some constants etc. I left it at 16Mb, as my machine
 * even cannot be extended past that (ok, but it was cheap :-)
 * I've tried to show which constants to change by having
 * some kind of marker at them (search for "16Mb"), but I
 * won't guarantee that's all :-( )
 */
.align 2	# tsz: #book2 按4字节方式对齐
setup_paging:
	movl $1024*5,%ecx		/* 5 pages - pg_dir+4 page tables */
	xorl %eax,%eax
	xorl %edi,%edi			/* pg_dir is at 0x000 */
	cld;rep;stosl	# tsz: #personal cld为clear df flag,设置edi为自增方向；stosl使得eax中的内容保存到es:di的位置，并使edi每次自增4B,重复1024*5次，也就是以上一段完成了内存清零;注意格式，循环的代码在下方	#ques 这里怎么确定循环的范围?
	movl $pg0+7,pg_dir		/* set present bit/user r/w */	# tsz: #course 在页目录表中刷各个页表的属性设置，那三位是u/s;r/w,present，111表示用户u,rw,p;000代表内核s,r,不存在;#ques 明明是内核的页表，为什么设置成用户u?#answ from cxh 0号进程在转用户态后依然需要访问页，如果设成3会导致move_to_usr_mode里的iret下条指令PAGE_FAULT
	movl $pg1+7,pg_dir+4		/*  --------- " " --------- */
	movl $pg2+7,pg_dir+8		/*  --------- " " --------- */
	movl $pg3+7,pg_dir+12		/*  --------- " " --------- */
	movl $pg3+4092,%edi	# tsz: #personal 移到最后一个页表项 
	movl $0xfff007,%eax		/*  16Mb - 4096 + 7 (r/w user,p) */	# tsz: #personal 最后一个页表项的值(指向的地址和属性)
	std	# tsz: #personal std是set df flag，设置edi自减方向
1:	stosl			/* fill pages backwards - more efficient :-) */
	subl $0x1000,%eax	# tsz: #personal 指向的地址-4k 
	jge 1b	# tsz: #book2 小于0说明全部填好了 
	xorl %eax,%eax		/* pg_dir is at 0x0000 */
	movl %eax,%cr3		/* cr3 - page directory start */	# tsz: #book CR3高20位指向页目录表基地址 
	movl %cr0,%eax
	orl $0x80000000,%eax
	movl %eax,%cr0		/* set paging (PG) bit */
	ret			/* this also flushes prefetch-queue */

.align 2
.word 0
idt_descr:	# tsz: #personal 新的idt描述符，和gdt一样大、一样的表项大小、一样的表项数量，指向了新创建的idt表
	.word 256*8-1		# idt contains 256 entries
	.long idt
.align 2
.word 0
gdt_descr:
	.word 256*8-1		# so does gdt (not that that's any
	.long gdt		# magic number, but it works for me :^)

	.align 8
idt:	.fill 256,8,0		# idt is uninitialized	# tsz: #book #personal 新构建的idt表，每个表项都未初始化，起始位置0x54AA；.fill repeat,size,value；故意将idt、gdt设置在这么后面，防止被覆盖

gdt:	.quad 0x0000000000000000	/* NULL descriptor */	# tsz: #book #personal 起始位置为0x54B2；.quad定义一个4字(8B) 
	.quad 0x00c09a0000000fff	/* 16Mb */	# tsz: #book 段限长变成了16MB
	.quad 0x00c0920000000fff	/* 16Mb */
	.quad 0x0000000000000000	/* TEMPORARY - don't use */	# tsz: #question 为什么多此一举?
	.fill 252,8,0			/* space for LDT's and TSS's etc */	# tsz: #personal 剩下项填0
