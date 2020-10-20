/*
 *  linux/kernel/fork.c
 *
 *  (C) 1991  Linus Torvalds
 */

/*
 *  'fork.c' contains the help-routines for the 'fork' system call
 * (see also system_call.s), and some misc functions ('verify_area').
 * Fork is rather simple, once you get the hang of it, but the memory
 * management can be a bitch. See 'mm/mm.c': 'copy_page_tables()'
 */
#include <errno.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <asm/segment.h>
#include <asm/system.h>

// 写页面验证。若页面不可写，则复制页面。
extern void write_verify(unsigned long address);

long last_pid=0;    // 最新进程号，其值会由get_empty_process生成。

// 进程空间区域写前验证函数
// 对于80386 CPU，在执行特权级0代码时不会理会用户空间中的页面是否是也保护的，
// 因此在执行内核代码时用户空间中数据页面来保护标志起不了作用，写时复制机制
// 也就失去了作用。verify_area()函数就用于此目的。但对于80486或后来的CPU，其
// 控制寄存器CRO中有一个写保护标志WP(位16)，内核可以通过设置该标志来禁止特权
// 级0的代码向用户空间只读页面执行写数据，否则将导致发生写保护异常。从而486
// 以上CPU可以通过设置该标志来达到本函数的目的。
// 该函数对当前进程逻辑地址从addr到addr+size这一段范围以页为单位执行写操作前
// 的检测操作。由于检测判断是以页面为单位进行操作，因此程序首先需要找出addr所
// 在页面开始地址start，然后start加上进程数据段基址，使这个start变成CPU 4G线性
// 空间中的地址。最后循环调用write_verify()对指定大小的内存空间进行写前验证。
// 若页面是只读的，则执行共享检验和复制页面操作。
void verify_area(void * addr,int size)
{
	unsigned long start;

    // 首先将起始地址start调整为其所在左边界开始位置，同时相应地调整验证区域
    // 大小。下句中的start& 0xfff 用来获得指定起始位置addr(也即start)在所在
    // 页面中的偏移值，原验证范围size加上这个偏移值即扩展成以addr所在页面起始
    // 位置开始的范围值。因此在下面也需要把验证开始位置start调整成页面边界值。
	start = (unsigned long) addr;
	size += start & 0xfff;
	start &= 0xfffff000;            // 此时start是当前进程空间中的逻辑地址。
    // 下面start加上进程数据段在线性地址空间中的起始基址，变成系统整个线性空间
    // 中的地址位置。对于linux-0.11内核，其数据段和代码在线性地址空间中的基址
    // 和限长均相同。
	start += get_base(current->ldt[2]);
	while (size>0) {
		size -= 4096;
		write_verify(start);
		start += 4096;
	}
}

// 复制内存页表
// 参数nr是新任务号：p是新任务数据结构指针。该函数为新任务在线性地址空间中
// 设置代码段和数据段基址、限长，并复制页表。由于Linux系统采用了写时复制
// (copy on write)技术，因此这里仅为新进程设置自己的页目录表项和页表项，而
// 没有实际为新进程分配物理内存页面。此时新进程与其父进程共享所有内存页面。
// 操作成功返回0，否则返回出错号。
int copy_mem(int nr,struct task_struct * p)	// tsz: #course 内存被等分
{
	unsigned long old_data_base,new_data_base,data_limit;
	unsigned long old_code_base,new_code_base,code_limit;

    // 首先取当前进程局部描述符表中代表中代码段描述符和数据段描述符项中的
    // 的段限长(字节数)。0x0f是代码段选择符：0x17是数据段选择符。然后取
    // 当前进程代码段和数据段在线性地址空间中的基地址。由于Linux-0.11内核
    // 还不支持代码和数据段分立的情况，因此这里需要检查代码段和数据段基址
    // 和限长是否都分别相同。否则内核显示出错信息，并停止运行。
	code_limit=get_limit(0x0f);	// tsz: #course 在sched.h中；根据ldtr，使用的是父进程的ldt内容
	data_limit=get_limit(0x17);
	old_code_base = get_base(current->ldt[1]);
	old_data_base = get_base(current->ldt[2]);
	if (old_data_base != old_code_base)
		panic("We don't support separate I&D");
	if (data_limit < code_limit)
		panic("Bad data_limit");
    // 然后设置创建中的新进程在线性地址空间中的基地址等于(64MB * 其任务号)，
    // 并用该值设置新进程局部描述符表中段描述符中的基地址。接着设置新进程
    // 的页目录表项和页表项，即复制当前进程(父进程)的页目录表项和页表项。
    // 此时子进程共享父进程的内存页面。正常情况下copy_page_tables()返回0，
    // 否则表示出错，则释放刚申请的页表项。
	new_data_base = new_code_base = nr * 0x4000000;	// tsz: #course 64M，这64M是进程的用户态用的；每个进程都分配64M，那么一共就会占用4GB(#personal 当然由于进程0不用这64MB，因此内存不会不够用);#note  注意这是映射关系，不是分配来的；#ques 16MB到64MB间的空间用来干什么了?
	p->start_code = new_code_base;	// tsz: #personal #note 从这里能找到这个空间的开始地址
	set_base(p->ldt[1],new_code_base);	// tsz: #course #think 更改基址，#ques 但是没改限长，为什么?#answ 为了安全共享父进程内存;#ques 那自己段限长不够用怎么办?
	set_base(p->ldt[2],new_data_base);
	if (copy_page_tables(old_data_base,new_data_base,data_limit)) {	// tsz: #course 传的是父进程数据段的限长，依然是640K的限长;
		printk("free_page_tables: from copy_mem\n");
		free_page_tables(new_data_base,data_limit);
		return -ENOMEM;
	}
	return 0;
}

/*
 *  Ok, this is the main fork-routine. It copies the system process
 * information (task[nr]) and sets up the necessary registers. It
 * also copies the data segment in it's entirety.
 */
// 复制进程
// 该函数的参数进入系统调用中断处理过程开始，直到调用本系统调用处理过程
// 和调用本函数前时逐步压入栈的各寄存器的值。这些在system_call.s程序中
// 逐步压入栈的值(参数)包括：
// 1. CPU执行中断指令压入的用户栈地址ss和esp,标志寄存器eflags和返回地址cs和eip;
// 2. 在刚进入system_call时压入栈的段寄存器ds、es、fs和edx、ecx、ebx；
// 3. 调用sys_call_table中sys_fork函数时压入栈的返回地址(用参数none表示)；
// 4. 在调用copy_process()分配任务数组项号。
int copy_process(int nr,long ebp,long edi,long esi,long gs,long none,	// tsz: #impo 右序进栈，所以看到最右边的参数是int80压的栈，还有一些栈是在system_call中压的栈，最后一部分栈是sys_fork压的栈；nr是eax，是find_empty_process的返回值;这一行的none是call sys_call_table(,%eax,4)压的栈，剩下的是在sys_fork中压的栈
		long ebx,long ecx,long edx,	// tsz: #personal 这两行的参数来自于system_call中的压栈
		long fs,long es,long ds,
		long eip,long cs,long eflags,long esp,long ss)	// tsz: #personal 这一行的参数来自于int80的压栈
{
	struct task_struct *p;
	int i;
	struct file *f;

    // 首先为新任务数据结构分配内存。如果内存分配出错，则返回出错码并退出。
    // 然后将新任务结构指针放入任务数组的nr项中。其中nr为任务号，由前面
    // find_empty_process()返回。接着把当前进程任务结构内容复制到刚申请到
    // 的内存页面p开始处。
	p = (struct task_struct *) get_free_page();	// tsz: #course 能玩页了，pg打开了，cr3和页目录表初始化好了，mem_map，注意不是用union来转换类型，而是用task_struct;#impo 回去看这个函数，这个函数重要；作用为将父进程的task_struct的内容复制过来（当然只复制了一个task_struct的内容，没有copy stack的内容）
	// tsz: #personal #note 每个进程最多申请(64/4)+1=17个page，63个进程最多申请1071个page，而mem_map管理着4284个page，应该是够的
	if (!p)
		return -EAGAIN;
	task[nr] = p;	// tsz: #personal 已经有了调度的资格
	*p = *current;	/* NOTE! #note this doesn't copy the supervisor stack */	// tsz: #course #personal current是指向当前task_struct的指针；在sched.c中初始化为指向进程0的task_struct;不用修改自己的信息，此时其实已经能跑了，也能调度了；#think 复制父进程的struct有多少意义?
    // 随后对复制来的进程结构内容进行一些修改，作为新进程的任务结构。先将
    // 进程的状态置为不可中断等待状态，以防止内核调度其执行。然后设置新进程
    // 的进程号pid和父进程号father，并初始化进程运行时间片值等于其priority值
    // 接着复位新进程的信号位图、报警定时值、会话(session)领导标志leader、进程
    // 及其子进程在内核和用户态运行时间统计值，还设置进程开始运行的系统时间start_time.
	p->state = TASK_UNINTERRUPTIBLE;	// tsz: #course 设置其现在不能被调度（非抢占式不加也行，timer看到在内核态会缩回去，抢占式必须得加）
	p->pid = last_pid;              // 新进程号。也由find_empty_process()得到。
	p->father = current->pid;       // 设置父进程
	p->counter = p->priority;       // 运行时间片值
	p->signal = 0;                  // 信号位图置0
	p->alarm = 0;                   // 报警定时值(滴答数)
	p->leader = 0;		/* process leadership doesn't inherit */
	p->utime = p->stime = 0;        // 用户态时间和和心态运行时间
	p->cutime = p->cstime = 0;      // 子进程用户态和和心态运行时间
	p->start_time = jiffies;        // 进程开始运行时间(当前时间滴答数)	// tsz: #personal 就是0，定义在sched.c中
    // 再修改任务状态段TSS数据，由于系统给任务结构p分配了1页新内存，所以(PAGE_SIZE+
    // (long)p)让esp0正好指向该页顶端。ss0:esp0用作程序在内核态执行时的栈。另外，
    // 每个任务在GDT表中都有两个段描述符，一个是任务的TSS段描述符，另一个是任务的LDT
    // 表描述符。下面语句就是把GDT中本任务LDT段描述符和选择符保存在本任务的TSS段中。
    // 当CPU执行切换任务时，会自动从TSS中把LDT段描述符的选择符加载到ldtr寄存器中。
	p->tss.back_link = 0;
	p->tss.esp0 = PAGE_SIZE + (long) p;     // 任务内核态栈指针。	// tsz: #personal p是task_union的开始地址，加个PAGE_SIZE就是栈底；#ques ss0:esp0是否相当于在做esb的作用?
	p->tss.ss0 = 0x10;                      // 内核态栈的段选择符(与内核数据段相同)
	p->tss.eip = eip;                       // 指令代码指针	// tsz: #course 3特权，int80后面那句的地址；#personal #impo 这些压栈的内容进行手动复制的原因在于，进程0没有发生调度，可能这些即时的状态没有被保存在tss中
	p->tss.eflags = eflags;                 // 标志寄存器	// tsz: #course #impo eflags在内存，dangerous，将eflags的iopl修改成3就能为所欲为（滑稽）；#impo 可以推到tss、task_struct的其它字段
	p->tss.eax = 0;                         // #note 这是当fork()返回时新进程会返回0的原因所在	// tsz: #course 写死了，在执行Int80后面的一句if(__res>=0)可以用来判断当前进程到底子进程还是父进程
	p->tss.ecx = ecx;
	p->tss.edx = edx;
	p->tss.ebx = ebx;
	p->tss.esp = esp;
	p->tss.ebp = ebp;
	p->tss.esi = esi;
	p->tss.edi = edi;
	p->tss.es = es & 0xffff;                // 段寄存器仅16位有效
	p->tss.cs = cs & 0xffff;
	p->tss.ss = ss & 0xffff;
	p->tss.ds = ds & 0xffff;
	p->tss.fs = fs & 0xffff;
	p->tss.gs = gs & 0xffff;
	p->tss.ldt = _LDT(nr);                  // 任务局部表描述符的选择符( )	// tsz: #personal 注意这是tss中的ldt，所以是LDT的的选择符
	p->tss.trace_bitmap = 0x80000000;       // 高16位有效	// tsz: #personal #ques
    // 如果当前任务使用了协处理器，就保存其上下文。汇编指令clts用于清除控制寄存器CRO中
    // 的任务已交换(TS)标志。每当发生任务切换，CPU都会设置该标志。该标志用于管理数学协
    // 处理器：如果该标志置位，那么每个ESC指令都会被捕获(异常7)。如果协处理器存在标志MP
    // 也同时置位的话，那么WAIT指令也会捕获。因此，如果任务切换发生在一个ESC指令开始执行
    // 之后，则协处理器中的内容就可能需要在执行新的ESC指令之前保存起来。捕获处理句柄会
    // 保存协处理器的内容并复位TS标志。指令fnsave用于把协处理器的所有状态保存到目的操作数
    // 指定的内存区域中。
	if (last_task_used_math == current)
		__asm__("clts ; fnsave %0"::"m" (p->tss.i387));
    // 接下来复制进程页表。即在线性地址空间中设置新任务代码段和数据段描述符中的基址和限长，
    // 并复制页表。如果出错(返回值不是0)，则复位任务数组中相应项并释放为该新任务分配的用于
    // 任务结构的内存页。
	if (copy_mem(nr,p)) {	// tsz: #personal 如果复制出错
		task[nr] = NULL;
		free_page((long) p);
		return -EAGAIN;
	}
    // 如果父进程中有文件是打开的，则将对应文件的打开次数增1，因为这里创建的子进程会与父
    // 进程共享这些打开的文件。将当前进程(父进程)的pwd，root和executable引用次数均增1.
    // 与上面同样的道理，子进程也引用了这些i节点。
	for (i=0; i<NR_OPEN;i++)
		if ((f=p->filp[i]))
			f->f_count++;
	if (current->pwd)
		current->pwd->i_count++;
	if (current->root)
		current->root->i_count++;
	if (current->executable)
		current->executable->i_count++;
    // 随后GDT表中设置新任务TSS段和LDT段描述符项。这两个段的限长均被设置成104字节。
    // set_tss_desc()和set_ldt_desc()在system.h中定义。"gdt+(nr<<1)+FIRST_TSS_ENTRY"是
    // 任务nr的TSS描述符项在全局表中的地址。因为每个任务占用GDT表中2项，因此上式中
    // 要包括'(nr<<1)'.程序然后把新进程设置成就绪态。另外在任务切换时，任务寄存器tr由
    // CPU自动加载。最后返回新进程号。
	set_tss_desc(gdt+(nr<<1)+FIRST_TSS_ENTRY,&(p->tss));
	set_ldt_desc(gdt+(nr<<1)+FIRST_LDT_ENTRY,&(p->ldt));	// tsz: #personal 直接用了父进程的ldt描述符
	p->state = TASK_RUNNING;	/* do this last, just in case */	// tsz: #course 就绪态
	return last_pid;
}

// 为新进程取得不重复的进程号last_pid.函数返回在任务数组中的任务号(数组项)。
int find_empty_process(void)
{
	int i;

    // 首先获取新的进程号。如果last_pid增1后超出进程号的整数表示范围，则重新从1开始
    // 使用pid号。然后在任务数组中搜索刚设置的pid号是否已经被任何任务使用。如果是则
    // 跳转到函数开始出重新获得一个pid号。接着在任务数组中为新任务寻找一个空闲项，并
    // 返回项号。last_pid是一个全局变量，不用返回。如果此时任务数组中64个项已经被全部
    // 占用，则返回出错码。
	repeat:
		if ((++last_pid)<0) last_pid=1;
		for(i=0 ; i<NR_TASKS ; i++)
			if (task[i] && task[i]->pid == last_pid) goto repeat;	// tsz: #book 验证last_pid有效;#personal 因为:1)当last_pi置1后，每次加一都不能保证last_pid有效;2)进行一定的分配之后，进程的last_pid是混乱的，因此要遍历整个task数组检查
	for(i=1 ; i<NR_TASKS ; i++)         // 任务0项被排除在外
		if (!task[i])
			return i;
	return -EAGAIN;
}
