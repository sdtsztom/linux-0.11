/*
 *  linux/kernel/exit.c
 *
 *  (C) 1991  Linus Torvalds
 */

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/tty.h>
#include <asm/segment.h>

// 把进程置为睡眠状态，直到收到信号
int sys_pause(void);
// 关闭指定文件的系统调用
int sys_close(int fd);

//// 释放指定进程占用的任务槽及其任务数据结构占用的内存页面。
// 参数p是任务数据结构指针。该函数在后面的sys_kill()和sys_waitpid()函数中被调用。
// 扫描任务指针数组表task[]以寻找指定的任务。如果找到，则首先清空该任务槽，然后
// 释放该任务数据结构所占用的内存页面，最后执行调度函数并在返回时立即退出。如果
// 在任务数组表中没有找到指定任务对应的项，则内核panic. ;-)
void release(struct task_struct * p)
{
	int i;

	if (!p)                         // 如果进程数据结构指针是NULL，则什么也不做，退出。
		return;
	for (i=1 ; i<NR_TASKS ; i++)    // 扫描任务数组，寻找指定任务
		if (task[i]==p) {
			task[i]=NULL;           // 置空该任务项并释放相关内存页。
			free_page((long)p);
			schedule();             // 重新调度(似乎没有必要)
			return;
		}
	panic("trying to release non-existent task");       // 指定任务若不存在则死机
}

//// 向指定任务p发送信号sig, 权限priv。
// 参数：sig - 信号值；p - 指定任务的指针；priv - 强制发送信号的标志。即不需要考虑进程
// 用户属性或级别而能发送信号的权利。该函数首先判断参数的正确性，然后判断条件是否满足。
// 如果满足就向指定进程发送信号sig并退出，否则返回为许可错误号。
static inline int send_sig(long sig,struct task_struct * p,int priv)
{
    // 若信号不正确或任务指针为空，则出错退出。
	if (!p || sig<1 || sig>32)
		return -EINVAL;
    // 如果强制发送标志置位，或者当前进程的有效用户标识符(euid)就是指定进程的euid（也
    // 即是自己），或者当前进程是超级用婚，则向进程p发送信号sig，即在进程p位图中添加该
    // 信号，否则出错退出。其中suser()定义为(current->euid==0)，用于判断是否是超级用户。
	if (priv || (current->euid==p->euid) || suser())
		p->signal |= (1<<(sig-1));
	else
		return -EPERM;
	return 0;
}

//// 终止会话(session)
static void kill_session(void)
{
	struct task_struct **p = NR_TASKS + task;   // 指针*p首先指向任务数组最末端
	
    // 扫描任务指针数组，对于所有的任务(除任务0以外)，如果其会话号session等于当前进程的
    // 会话号就向它发送挂断进程信号SIGHUP。
	while (--p > &FIRST_TASK) {
		if (*p && (*p)->session == current->session)
			(*p)->signal |= 1<<(SIGHUP-1);      // 发送挂断进程信号
	}
}

/*
 * XXX need to check permissions needed to send signals to process
 * groups, etc. etc.  kill() permissions semantics are tricky!
 */
//// 系统调用kill()可用于向任何进程或进程组发送任何信号，而并非只是杀死进程。:-)
// 参数pid是进程号；sig是需要发送的信号。
// 如果pid > 0, 则信号被发送给进程号是pid的进程。
// 如果pid = 0, 那么信号就会被发送给当前进程的进程组中的所有进程。
// 如果pid = -1,则信号sig就会发送给除第一个进程(初始进程init)外的所有进程
// 如果pid < -1,则信号sig将发送给进程组-pid的所有进程。
// 如果信号sig=0,则不发送信号，但仍会进行错误检查。如果成功则返回0.
// 该函数扫描任务数组表，并根据pid的值对满足条件的进程发送指定信号sig。若pid=0,
// 表明当前进程是进程组组长，因此需要向所有组内进程强制发送信号sig.
int sys_kill(int pid,int sig)
{
	struct task_struct **p = NR_TASKS + task;
	int err, retval = 0;

	if (!pid) while (--p > &FIRST_TASK) {
		if (*p && (*p)->pgrp == current->pid) 
			if ((err=send_sig(sig,*p,1)))           // 强制发送信号
				retval = err;
	} else if (pid>0) while (--p > &FIRST_TASK) {
		if (*p && (*p)->pid == pid) 
			if ((err=send_sig(sig,*p,0)))
				retval = err;
	} else if (pid == -1) while (--p > &FIRST_TASK) {
		if ((err = send_sig(sig,*p,0)))
			retval = err;
	} else while (--p > &FIRST_TASK)
		if (*p && (*p)->pgrp == -pid)
			if ((err = send_sig(sig,*p,0)))
				retval = err;
	return retval;
}

//// 通知父进程 - 向进程pid发送信号SIGCHLD；默认情况下子进程将停止或终止。
// 如果没有找到父进程，则自己释放。但根据POSIX.1要求，若父进程已先行终止，
// 则子进程应该被初始进程1收容。
static void tell_father(int pid)
{
	int i;

	if (pid)
        // 扫描进城数组表，寻找指定进程pid，并向其发送子进程将停止或终止信号SIGCHLD。
		for (i=0;i<NR_TASKS;i++) {
			if (!task[i])
				continue;
			if (task[i]->pid != pid)
				continue;
			task[i]->signal |= (1<<(SIGCHLD-1));
			return;
		}
/* if we don't find any fathers, we just release ourselves */
/* This is not really OK. Must change it to make father 1 */
	printk("BAD BAD - no father found\n\r");
	release(current);               // 如果没有找到父进程，则自己释放
}

//1、为什么开始启动计算机的时候，执行的是BIOS代码而不是操作系统自身的代码？
//
//最开始启动计算机的时候，计算机内存未初始化，没有任何程序。而因为CPU只能读取内存中的程序，所以必须将操作系统先加载进内存当中。需要使用BIOS。在加电后， BIOS 需要完成一些检测工作，设置实模式下的中断向量表和服务程序，并将操作系统的引导扇区加载至 0x7C00 处，然后将跳转至 0x7C00运行操作系统自身的代码。所以计算机启动最开始运行的是BIOS代码。
//
// 
//
//2、为什么BIOS只加载了一个扇区，后续扇区却是由boots ect代码加载？为什么BIOS没有直接把所有需要加载的扇区都加载？
//
//BIOS和操作系统的开发通常是不同的团队，按固定的规则约定，可以进行灵活的各自设计相应的部分。BIOS接到启动操作系统命令后，只从启动扇区将代码加载至0x7c00(BOOTSEG)位置，而后续扇区由bootsect代码加载，这些代码由编写系统的用户负责，与之前BIOS无关。这样构建的好处是站在整个体系的高度，统一设计和统一安排，简单而有效。
//
//如果要使用BIOS进行加载，而且加载完成之后再执行，则需要很长的时间，因此Linux采用的是边执行边加载的方法。
//
// 
//
//3、为什么BIOS把bootsect加载到0x07c00，而不是0x00000？加载后又马上挪到0x90000处，是何道理？为什么不一次加载到位？
//
//加载0x07c00是BIOS提前约定设置的，不能加载到0x00000是因为从0x00000开始到0x003ff这1KB内存空间都是BIOS首先约定进行加载中断向量表的地方，不能进行覆盖。
//
//而后挪到0x90000处是操作系统开始根据自己的需要安排内存了，具体原因如下：
//
//① 内核会使用启动扇区中的一些数据，如第 508、509 字节处的 ROOT_DEV；
//
//② 依据系统对内存的规划，内核占用 0x00000 开始的空间，因此 0x07c00 可能会被覆盖。
//
// 
//
//4、bootsect、setup、head程序之间是怎么衔接的？给出代码证据。
//
//① bootsect跳转到setup程序：jmpi 0,SETUPSEG;
//
//bootsect首先利用int 0x13中断分别加载setup程序及system模块，待bootsect程序的任务完成之后，执行代码jmpi 0,SETUPSEG。由于 bootsect 将 setup 段加载到了 SETUPSEG:0 （0x90200）的地方,在实模式下，CS:IP指向setup程序的第一条指令，此时setup开始执行。
//
//② setup跳转到head程序：jmpi 0,8
//
//执行setup后，内核被移到了0x00000处，CPU变为保护模式，执行jmpi 0,8
//
//并加载了中断描述符表和全局描述符表。该指令执行后跳转到以GDT第2项中的 base_addr 为基地址，以0为偏移量的位置，其中base_addr为0。由于head放置在内核的头部，因此程序跳转到head中执行。
//
// 
//
//5、setup程序的最后是jmpi 0,8 ，为什么这个8不能简单的当作阿拉伯数字8看待，究竟有什么内涵？
//
//此时为32位保护模式，“0”表示段内偏移，“8”表示段选择符。转化为二进制：1000
//
//最后两位00表示内核特权级，第三位0表示 GDT 表，第四位1表示根据GDT中的第2项来确定代码段的段基址和段限长等信息。可以得到代码是从head 的开始位置，段基址 0x00000000、偏移为 0 处开始执行的。
//
// 
//
//// 程序退出处理函数。
// 该函数将把当前进程置为TASK_ZOMBIE状态，然后去执行调度函数schedule()，不再返回。
// 参数code是退出状态码，或称为错误码。
int do_exit(long code)
{
	int i;
    // 首先释放当前进程代码段和数据段所占的内存页。函数free_page_tables()的第一个参数
    // (get_base()返回值)指明在CPU线性地址空间中起始基地址，第2个(get_limit()返回值)
    // 说明欲释放的字节长度值。get_base()宏中的current->ldt[1]给出进程代码段描述符的
    // 位置(current->ldt[2]给出进程代码段描述符的位置)；get_limit()中0x0f是进程代码段
    // 的选择符(0x17是进城数据段的选择符)。即在取段基地址时使用该段的描述符所处地址作为
    // 参数，取段长度时使用该段的选择符作为参数。free_page_tables()函数位于mm/memory.c
    // 文件中。
	free_page_tables(get_base(current->ldt[1]),get_limit(0x0f));
	free_page_tables(get_base(current->ldt[2]),get_limit(0x17));
    // 如果当前进程有子进程，就将子进程的father置为1(其父进程改为进程1，即init进程)。
    // 如果该子进程已经处于僵死(ZOMBIE)状态，则向进程1发送子进程中止信号SIGCHLD。
	for (i=0 ; i<NR_TASKS ; i++)
		if (task[i] && task[i]->father == current->pid) {
			task[i]->father = 1;
			if (task[i]->state == TASK_ZOMBIE)
				/* assumption task[1] is always init */
				(void) send_sig(SIGCHLD, task[1], 1);
		}
    // 关闭当前进程打开着的所有文件。
	for (i=0 ; i<NR_OPEN ; i++)
		if (current->filp[i])
			sys_close(i);
    // 对当前进程的工作目录pwd，根目录root以及执行程序文件的i节点进行同步操作，放回
    // 各个i节点并分别置空(释放)。
	iput(current->pwd);
	current->pwd=NULL;
	iput(current->root);
	current->root=NULL;
	iput(current->executable);
	current->executable=NULL;
    // 如果当前进程是会话头领(leader)进程并且其有控制终端，则释放该终端。
	if (current->leader && current->tty >= 0)
		tty_table[current->tty].pgrp = 0;
    // 如果当前进程上次使用过协处理器，则将last_task_used_math置空。
	if (last_task_used_math == current)
		last_task_used_math = NULL;
    // 如果当前进程是leader进程，则终止该会话的所有相关进程。
	if (current->leader)
		kill_session();
    // 把当前进程置为僵死状态，表明当前进程已经释放了资源。并保存将由父进程读取的退出码。
	current->state = TASK_ZOMBIE;
	current->exit_code = code;
    // 通知父进程，也即向父进程发送信号SIGCHLD - 子进程将停止或终止。
	tell_father(current->father);
	schedule();                     // 重新调度进程运行，以让父进程处理僵死其他的善后事宜。
    // 下面的return语句仅用于去掉警告信息。因为这个函数不返回，所以若在函数名前加关键字
    // volatile，就可以告诉gcc编译器本函数不会返回的特殊情况。这样可让gcc产生更好一些的代码，
    // 并且可以不用再写return语句也不会产生假警告信息。
	return (-1);	/* just to suppress warnings */
}

//// 系统调用exit()，终止进程。
// 参数error_code是用户程序提供的退出状态信息，只有低字节有效。把error_code左移8bit是wait()或
// waitpid()函数的要求。低字节中将用来保存wait()的状态信息。例如，如果进程处理暂停状态(TASK_STOPPED),
// 那么其低字节就等于0x7f. wait()或waitpid()利用这些宏就可以取得子进程的退出状态码或子进程终止的原因。
int sys_exit(int error_code)
{
	return do_exit((error_code&0xff)<<8);
}

//// 系统调用waipid().挂起当前进程，直到pid指定的子进程退出(终止)或收到要求终止该进程的信号，
// 或者是需要调用一个信号句柄(信号处理程序)。如果pid所指向的子进程早已退出(已成所谓的僵死进程)，
// 则本调用将立刻返回。子进程使用的所有资源将释放。
// 如果pid > 0，表示等待进程号等于pid的子进程。
// 如果pid = 0, 表示等待进程组号等于当前进程组号的任何子进程。
// 如果pid < -1,表示等待进程组号等于pid绝对值的任何子进程。
// 如果pid = -1,表示等待任何子进程。
// 如 options = WUNTRACED,表示如果子进程是停止的，也马上返回(无须跟踪)
// 若 options = WNOHANG, 表示如果没有子进程退出或终止就马上返回。
// 如果返回状态指针 stat_addr不为空，则就将状态信息保存到那里。
// 参数pid是进程号，*stat_addr是保存状态信息位置的指针，options是waitpid选项。
int sys_waitpid(pid_t pid,unsigned long * stat_addr, int options)
{
	int flag, code;             // flag标志用于后面表示所选出的子进程处于就绪或睡眠态。
	struct task_struct ** p;

	verify_area(stat_addr,4);
repeat:
	flag=0;
    // 从任务数组末端开始扫描所有任务，跳过空项、本进程项以及非当前进程的子进程项。
	for(p = &LAST_TASK ; p > &FIRST_TASK ; --p) {
		if (!*p || *p == current)
			continue;
		if ((*p)->father != current->pid)
			continue;
        // 此时扫描选择到的进程p肯定是当前进程的子进程。
        // 如果等待的子进程号pid>0，但与被扫描子进程p的pid不相等，说明它是当前进程另外的
        // 子进程，于是跳过该进程，接着扫描下一个进程。
		if (pid>0) {
			if ((*p)->pid != pid)
				continue;
        // 否则，如果指定等待进程的pid=0,表示正在等待进程组号等于当前进程组号的任何子进程。
        // 如果此时被扫描进程p的进程组号与当前进程的组号不等，则跳过。
		} else if (!pid) {
			if ((*p)->pgrp != current->pgrp)
				continue;
        // 否则，如果指定的pid < -1,表示正在等待进程组号等于pid绝对值的任何子进程。如果此时
        // 被扫描进程p的组号与pid的绝对值不等，则跳过。
		} else if (pid != -1) {
			if ((*p)->pgrp != -pid)
				continue;
		}
        // 如果前3个对pid的判断都不符合，则表示当前进程正在等待其任何子进程，也即pid=-1的情况，
        // 此时所选择到的进程p或者是其进程号等于指定pid，或者是当前进程组中的任何子进程，或者
        // 是进程号等于指定pid绝对值的子进程，或者是任何子进程(此时指定的pid等于-1).接下来根据
        // 这个子进程p所处的状态来处理。
		switch ((*p)->state) {
            // 子进程p处于停止状态时，如果此时WUNTRACED标志没有置位，表示程序无须立刻返回，于是
            // 继续扫描处理其他进程。如果WUNTRACED置位，则把状态信息0x7f放入*stat_addr，并立刻
            // 返回子进程号pid.这里0x7f表示的返回状态是wifstopped（）宏为真。
			case TASK_STOPPED:
				if (!(options & WUNTRACED))
					continue;
				put_fs_long(0x7f,stat_addr);
				return (*p)->pid;
            // 如果子进程p处于僵死状态，则首先把它在用户态和内核态运行的时间分别累计到当前进程
            // (父进程)中，然后取出子进程的pid和退出码，并释放该子进程。最后返回子进程的退出码和pid.
			case TASK_ZOMBIE:
				current->cutime += (*p)->utime;
				current->cstime += (*p)->stime;
				flag = (*p)->pid;                   // 临时保存子进程pid
				code = (*p)->exit_code;             // 取子进程的退出码
				release(*p);                        // 释放该子进程
				put_fs_long(code,stat_addr);        // 置状态信息为退出码值
				return flag;                        // 返回子进程的pid
            // 如果这个子进程p的状态既不是停止也不是僵死，那么就置flag=1,表示找到过一个符合
            // 要求的子进程，但是它处于运行态或睡眠态。
			default:
				flag=1;
				continue;
		}
	}
    // 在上面对任务数组扫描结束后，如果flag被置位，说明有符合等待要求的子进程并没有处于退出或
    // 僵死状态。如果此时已设置WNOHANG选项(表示若没有子进程处于退出或终止态就立刻返回)，就
    // 立刻返回0，退出。否则把当前进程置为可中断等待状态并重新执行调度。当又开始执行本进程时，
    // 如果本进程没有收到除SIGCHLD以外的信号，则还是重复处理。否则，返回出错码‘中断系统调用’
    // 并退出。针对这个出错号用户程序应该再继续调用本函数等待子进程。
	if (flag) {
		if (options & WNOHANG)                  // options = WNOHANG,则立刻返回。
			return 0;
		current->state=TASK_INTERRUPTIBLE;      // 置当前进程为可中断等待态
		schedule();                             // 重新调度。
		if (!(current->signal &= ~(1<<(SIGCHLD-1))))
			goto repeat;
		else
			return -EINTR;                      // 返回出错码(中断的系统调用)
	}
    // 若没有找到符合要求的子进程，则返回出错码(子进程不存在)。
	return -ECHILD;
}


//6、保护模式在“保护”什么？它的“保护”体现在哪里？特权级的目的和意义是什么？分页有“保护”作用吗？p438-440
//
//（1） 保护模式在“保护”什么？它的“保护”体现在哪里？
//
//保护操作系统的安全，不受到恶意攻击。保护进程地址空间。
//
//“保护”体现在
//
//打开保护模式后，CPU 的寻址模式发生了变化，基于 GDT 去获取代码或数据段的基址，相当于增加了一个段位寄存器。防止了对代码或数据段的覆盖以及代码段自身的访问超限。对描述符所描述的对象进行保护：在 GDT、 LDT 及 IDT 中，均有对应界限、特权级等；在不同特权级间访问时，系统会对 CPL、 RPL、 DPL、 IOPL 等进行检验，同时限制某些特殊指令如 lgdt, lidt,cli 等的使用；分页机制中 PDE 和 PTE 中的 R/W 和 U/S 等提供了页级保护，分页机制通过将线性地址与物理地址的映射，提供了对物理地址的保护。
//
//（2）特权级的目的和意义是什么？
//
//特权级机制目的是为了进行合理的管理资源，保护高特权级的段。
//
//意义是进行了对系统的保护，对操作系统的“主奴机制”影响深远。Intel 从硬件上禁止低特权级代码段使用部分关键性指令，通过特权级的设置禁止用户进程使用 cli、 sti 等指令。将内核设计成最高特权级，用户进程成为最低特权级。这样，操作系统可以访问 GDT、 LDT、 TR，而 GDT、 LDT 是逻辑地址形成线性地址的关键，因此操作系统可以掌控线性地址。物理地址是由内核将线性地址转换而成的，所以操作系统可以访问任何物理地址。而用户进程只能使用逻辑地址。总之，特权级的引入对操作系统内核进行保护。
//
//（3）分页有“保护”作用吗？
//
//分页机制有保护作用，使得用户进程不能直接访问内核地址，进程间也不能相互访问。用户进程只能使用逻辑地址，而逻辑地址通过内核转化为线性地址，根据内核提供的专门为进程设计的分页方案，由MMU非直接映射转化为实际物理地址形成保护。此外，通过分页机制，每个进程都有自己的专属页表，有利于更安全、高效的使用内存，保护每个进程的地址空间。
//
//为什么特权级是基于段的？（超纲备用）
//
//通过段，系统划分了内核代码段、内核数据段、用户代码段和用户数据段等不同的数据段，有些段是系统专享的，有些是和用户程序共享的，因此就有特权级的概念。
//
// 
//
//7、在setup程序里曾经设置过gdt，为什么在head程序中将其废弃，又重新设置了一个？为什么设置两次，而不是一次搞好？
//
//P33点评
//
// 
//
//8、进程0的task_struct在哪？具体内容是什么？
//
//进程0的task_struct位于内核数据区，因为在进程0未激活之前，使用的是boot阶段的user_stack，因此存储在user_stack中。
//
//具体内容如下：
//
//包含了进程 0 的进程状态、进程 0 的 LDT、进程 0 的 TSS 等等。其中 ldt 设置了代码段和堆栈段的基址和限长(640KB)，而 TSS 则保存了各种寄存器的值，包括各个段选择符。
//
//代码如下：(若未要求没时间可不写)
//
//INIT_TASK的定义见P68。
//
// 
//
//9、内核的线性地址空间是如何分页的？画出从0x000000开始的7个页（包括页目录表、页表所在页）的挂接关系图，就是页目录表的前四个页目录项、第一个个页表的前7个页表项指向什么位置？给出代码证据。
//
//如何分页
//
//head.s在setup_paging开始创建分页机制。将页目录表和4个页表放到物理内存的起始位置，从内存起始位置开始的5个页空间内容全部清零（每页4KB），然后设置页目录表的前4项，使之分别指向4个页表。然后开始从高地址向低地址方向填写4个页表，依次指向内存从高地址向低地址方向的各个页面。即将第4个页表的最后一项指向寻址范围的最后一个页面。即从0xFFF000开始的4kb 大小的内存空间。将第4个页表的倒数第二个页表项指向倒数第二个页面，即0xFFF000-0x1000开始的4KB字节的内存空间，依此类推。
//
//挂接关系图
//
//
//代码证据
//
//P39最下面
//
// 
//
//10、在head程序执行结束的时候，在idt的前面有184个字节的head程序的剩余代码，剩余了什么？为什么要剩余？
//
//剩余代码：
//
//包含代码段如下after_page_tables(栈中压入了些参数)、 ignore_int(初始化中断时的中断处理函数) 和 setup_paging(初始化分页)。
//
//剩余的原因：
//
//after_page_tables 中压入的参数，为内核进入 main 函数的跳转做准备。设计者在栈中压入了 L6: main，以使得系统出错时，返回到 L6 处执行。
//
//ignore_int 为中断处理函数，使用 ignore_int 将 idt 全部初始化，如果中断开启后存在使用了未设置的中断向量，那么将默认跳转到 ignore_int 处执行，使得系统不会跳转到随机的地方执行错误的代码。
//
//setup_paging 进行初始化分页，在该函数中对 0x0000 和 0x5000 的进行了初始化操作。该代码用于跳转到 main，即执行“ret”指令。
//
// 
//
/*
 *  linux/kernel/exit.c
 *
 *  (C) 1991  Linus Torvalds
 */

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/tty.h>
#include <asm/segment.h>

// 把进程置为睡眠状态，直到收到信号
int sys_pause(void);
// 关闭指定文件的系统调用
int sys_close(int fd);

//// 释放指定进程占用的任务槽及其任务数据结构占用的内存页面。
// 参数p是任务数据结构指针。该函数在后面的sys_kill()和sys_waitpid()函数中被调用。
// 扫描任务指针数组表task[]以寻找指定的任务。如果找到，则首先清空该任务槽，然后
// 释放该任务数据结构所占用的内存页面，最后执行调度函数并在返回时立即退出。如果
// 在任务数组表中没有找到指定任务对应的项，则内核panic. ;-)
void release(struct task_struct * p)
{
	int i;

	if (!p)                         // 如果进程数据结构指针是NULL，则什么也不做，退出。
		return;
	for (i=1 ; i<NR_TASKS ; i++)    // 扫描任务数组，寻找指定任务
		if (task[i]==p) {
			task[i]=NULL;           // 置空该任务项并释放相关内存页。
			free_page((long)p);
			schedule();             // 重新调度(似乎没有必要)
			return;
		}
	panic("trying to release non-existent task");       // 指定任务若不存在则死机
}

//// 向指定任务p发送信号sig, 权限priv。
// 参数：sig - 信号值；p - 指定任务的指针；priv - 强制发送信号的标志。即不需要考虑进程
// 用户属性或级别而能发送信号的权利。该函数首先判断参数的正确性，然后判断条件是否满足。
// 如果满足就向指定进程发送信号sig并退出，否则返回为许可错误号。
static inline int send_sig(long sig,struct task_struct * p,int priv)
{
    // 若信号不正确或任务指针为空，则出错退出。
	if (!p || sig<1 || sig>32)
		return -EINVAL;
    // 如果强制发送标志置位，或者当前进程的有效用户标识符(euid)就是指定进程的euid（也
    // 即是自己），或者当前进程是超级用婚，则向进程p发送信号sig，即在进程p位图中添加该
    // 信号，否则出错退出。其中suser()定义为(current->euid==0)，用于判断是否是超级用户。
	if (priv || (current->euid==p->euid) || suser())
		p->signal |= (1<<(sig-1));
	else
		return -EPERM;
	return 0;
}

//// 终止会话(session)
static void kill_session(void)
{
	struct task_struct **p = NR_TASKS + task;   // 指针*p首先指向任务数组最末端
	
    // 扫描任务指针数组，对于所有的任务(除任务0以外)，如果其会话号session等于当前进程的
    // 会话号就向它发送挂断进程信号SIGHUP。
	while (--p > &FIRST_TASK) {
		if (*p && (*p)->session == current->session)
			(*p)->signal |= 1<<(SIGHUP-1);      // 发送挂断进程信号
	}
}

/*
 * XXX need to check permissions needed to send signals to process
 * groups, etc. etc.  kill() permissions semantics are tricky!
 */
//// 系统调用kill()可用于向任何进程或进程组发送任何信号，而并非只是杀死进程。:-)
// 参数pid是进程号；sig是需要发送的信号。
// 如果pid > 0, 则信号被发送给进程号是pid的进程。
// 如果pid = 0, 那么信号就会被发送给当前进程的进程组中的所有进程。
// 如果pid = -1,则信号sig就会发送给除第一个进程(初始进程init)外的所有进程
// 如果pid < -1,则信号sig将发送给进程组-pid的所有进程。
// 如果信号sig=0,则不发送信号，但仍会进行错误检查。如果成功则返回0.
// 该函数扫描任务数组表，并根据pid的值对满足条件的进程发送指定信号sig。若pid=0,
// 表明当前进程是进程组组长，因此需要向所有组内进程强制发送信号sig.
int sys_kill(int pid,int sig)
{
	struct task_struct **p = NR_TASKS + task;
	int err, retval = 0;

	if (!pid) while (--p > &FIRST_TASK) {
		if (*p && (*p)->pgrp == current->pid) 
			if ((err=send_sig(sig,*p,1)))           // 强制发送信号
				retval = err;
	} else if (pid>0) while (--p > &FIRST_TASK) {
		if (*p && (*p)->pid == pid) 
			if ((err=send_sig(sig,*p,0)))
				retval = err;
	} else if (pid == -1) while (--p > &FIRST_TASK) {
		if ((err = send_sig(sig,*p,0)))
			retval = err;
	} else while (--p > &FIRST_TASK)
		if (*p && (*p)->pgrp == -pid)
			if ((err = send_sig(sig,*p,0)))
				retval = err;
	return retval;
}

//// 通知父进程 - 向进程pid发送信号SIGCHLD；默认情况下子进程将停止或终止。
// 如果没有找到父进程，则自己释放。但根据POSIX.1要求，若父进程已先行终止，
// 则子进程应该被初始进程1收容。
static void tell_father(int pid)
{
	int i;

	if (pid)
        // 扫描进城数组表，寻找指定进程pid，并向其发送子进程将停止或终止信号SIGCHLD。
		for (i=0;i<NR_TASKS;i++) {
			if (!task[i])
				continue;
			if (task[i]->pid != pid)
				continue;
			task[i]->signal |= (1<<(SIGCHLD-1));
			return;
		}
/* if we don't find any fathers, we just release ourselves */
/* This is not really OK. Must change it to make father 1 */
	printk("BAD BAD - no father found\n\r");
	release(current);               // 如果没有找到父进程，则自己释放
}

//11、为什么不用call，而是用ret“调用”main函数？画出调用路线图，给出代码证据。
//
//CALL 指令会将 EIP 的值自动压栈，保护返回现场，然后执行被调函数，当执行到被调函数的ret指令时，自动出栈给 EIP 并还原现场，继续执行CALL 的下一行指令。在由head程序向main函数跳转时，不需main函数返回；且因为main函数是最底层的函数，无更底层的函数进行返回。因此要达到既调用 main又不需返回，选择ret。
//
//调用路线图：见P42 图1-46。仿call示意图 下面部分
//
//代码证据：
//
// 
//
//12、用文字和图说明中断描述符表是如何初始化的，可以举例说明（比如：set_trap_gate(0,&divide_error)），并给出代码证据。
//
//（先画图见P54 图2-9然后解释）以set_trap_gate(0,&divide_error)为例，其中，n是0，gate_addr是&idt[0]，也就是idt的第一项中断描述符的地址；type是15，dpl（描述符特权级）是0；addr是中断服务程序divide_error(void)的入口地址。
//
//代码证据：P53 代码
//
// 
//
//13、在IA-32中，有大约20多个指令是只能在0特权级下使用，其他的指令，比如cli，并没有这个约定。奇怪的是，在Linux0.11中，3特权级的进程代码并不能使用cli指令，这是为什么？请解释并给出代码证据。
//
//根据Intel Manual，cli和sti指令与CPL和EFLAGS[IOPL]有关。通过IOPL来加以保护指令in,ins,out,outs,cli,sti等I/O敏感指令，只有CPL(当前特权级)<=IOPL才能执行，低特权级访问这些指令将会产生一个一般性保护异常。
//
//IOPL位于EFLAGS的12-13位，仅可通过iret来改变，INIT_TASK中IOPL为0，在move_to_user_mode中直接执行“pushfl \n\t”指令，继承了内核的EFLAGS。IOPL的指令仍然为0没有改变，所以用户进程无法调用cli指令。因此，通过设置 IOPL， 3特权级的进程代码不能使用 cli 等I/O敏感指令。
//
//具体代码：move_to_user_mode()此处一共两部分代码第一部分 P79
//
//#define move_to_user_mode() \
//
//__asm__(“movl %%esp, %%eax\n\t” \
//
//                   ……
//
//                   “pushfl\n\t” \                               // ELAGS 进栈
//
//                   ……
//
//”)
//
//第二部分代码见P 68 INIT_TASK
//
// 
//
//15、在system.h里
//
//#define _set_gate(gate_addr,type,dpl,addr) \
//
//__asm__ ("movw %%dx,%%ax\n\t" \
//
//         "movw %0,%%dx\n\t" \
//
//         "movl %%eax,%1\n\t" \
//
//         "movl %%edx,%2" \
//
//         : \
//
//         : "i" ((short) (0x8000+(dpl<<13)+(type<<8))), \
//
//         "o" (*((char *) (gate_addr))), \
//
//         "o" (*(4+(char *) (gate_addr))), \
//
//         "d" ((char *) (addr)),"a" (0x00080000))
//
//#define set_intr_gate(n,addr) \
//
//         _set_gate(&idt[n],14,0,addr)
//
// 
//
//#define set_trap_gate(n,addr) \
//
//         _set_gate(&idt[n],15,0,addr)
//
//#define set_system_gate(n,addr) \
//
//         _set_gate(&idt[n],15,3,addr)
//
//读懂代码。这里中断门、陷阱门、系统调用都是通过_set_gate设置的，用的是同一个嵌入汇编代码，比较明显的差别是dpl一个是3，另外两个是0，这是为什么？说明理由。
//
//答：
//
//当用户程序产生系统调用软中断后， 系统都通过system_call总入口找到具体的系统调用函数。 set_system_gate设置系统调用，须将 DPL设置为 3，允许在用户特权级（3）的进程调用，否则会引发 General Protection 异常。set_trap_gate 及 set_intr_gate 设置陷阱和中断为内核使用，需禁止用户进程调用，所以 DPL为 0。
//
// 
//
//16、进程0 fork进程1之前，为什么先调用move_to_user_mode()？用的是什么方法？解释其中的道理。
//
//Linux操作系统规定，除进程 0 之外， 所有进程都是由一个已有进程在用户态下完成创建的。需要将进程0通过调用move_to_user_mode()从内核态转换为用户态。进程0从0特权级到3特权级转换时采用的是模仿中断返回。
//
//设计者通过代码模拟 int（中断） 压栈， 当执行 iret 指令时， CPU 将SS,ESP,EFLAGS,CS,EIP 5 个寄存器的值按序恢复给 CPU， CPU之后翻转到 3 特权级去执行代码。
//
// 
//
//// 程序退出处理函数。
// 该函数将把当前进程置为TASK_ZOMBIE状态，然后去执行调度函数schedule()，不再返回。
// 参数code是退出状态码，或称为错误码。
int do_exit(long code)
{
	int i;
    // 首先释放当前进程代码段和数据段所占的内存页。函数free_page_tables()的第一个参数
    // (get_base()返回值)指明在CPU线性地址空间中起始基地址，第2个(get_limit()返回值)
    // 说明欲释放的字节长度值。get_base()宏中的current->ldt[1]给出进程代码段描述符的
    // 位置(current->ldt[2]给出进程代码段描述符的位置)；get_limit()中0x0f是进程代码段
    // 的选择符(0x17是进城数据段的选择符)。即在取段基地址时使用该段的描述符所处地址作为
    // 参数，取段长度时使用该段的选择符作为参数。free_page_tables()函数位于mm/memory.c
    // 文件中。
	free_page_tables(get_base(current->ldt[1]),get_limit(0x0f));
	free_page_tables(get_base(current->ldt[2]),get_limit(0x17));
    // 如果当前进程有子进程，就将子进程的father置为1(其父进程改为进程1，即init进程)。
    // 如果该子进程已经处于僵死(ZOMBIE)状态，则向进程1发送子进程中止信号SIGCHLD。
	for (i=0 ; i<NR_TASKS ; i++)
		if (task[i] && task[i]->father == current->pid) {
			task[i]->father = 1;
			if (task[i]->state == TASK_ZOMBIE)
				/* assumption task[1] is always init */
				(void) send_sig(SIGCHLD, task[1], 1);
		}
    // 关闭当前进程打开着的所有文件。
	for (i=0 ; i<NR_OPEN ; i++)
		if (current->filp[i])
			sys_close(i);
    // 对当前进程的工作目录pwd，根目录root以及执行程序文件的i节点进行同步操作，放回
    // 各个i节点并分别置空(释放)。
	iput(current->pwd);
	current->pwd=NULL;
	iput(current->root);
	current->root=NULL;
	iput(current->executable);
	current->executable=NULL;
    // 如果当前进程是会话头领(leader)进程并且其有控制终端，则释放该终端。
	if (current->leader && current->tty >= 0)
		tty_table[current->tty].pgrp = 0;
    // 如果当前进程上次使用过协处理器，则将last_task_used_math置空。
	if (last_task_used_math == current)
		last_task_used_math = NULL;
    // 如果当前进程是leader进程，则终止该会话的所有相关进程。
	if (current->leader)
		kill_session();
    // 把当前进程置为僵死状态，表明当前进程已经释放了资源。并保存将由父进程读取的退出码。
	current->state = TASK_ZOMBIE;
	current->exit_code = code;
    // 通知父进程，也即向父进程发送信号SIGCHLD - 子进程将停止或终止。
	tell_father(current->father);
	schedule();                     // 重新调度进程运行，以让父进程处理僵死其他的善后事宜。
    // 下面的return语句仅用于去掉警告信息。因为这个函数不返回，所以若在函数名前加关键字
    // volatile，就可以告诉gcc编译器本函数不会返回的特殊情况。这样可让gcc产生更好一些的代码，
    // 并且可以不用再写return语句也不会产生假警告信息。
	return (-1);	/* just to suppress warnings */
}

//// 系统调用exit()，终止进程。
// 参数error_code是用户程序提供的退出状态信息，只有低字节有效。把error_code左移8bit是wait()或
// waitpid()函数的要求。低字节中将用来保存wait()的状态信息。例如，如果进程处理暂停状态(TASK_STOPPED),
// 那么其低字节就等于0x7f. wait()或waitpid()利用这些宏就可以取得子进程的退出状态码或子进程终止的原因。
int sys_exit(int error_code)
{
	return do_exit((error_code&0xff)<<8);
}

//// 系统调用waipid().挂起当前进程，直到pid指定的子进程退出(终止)或收到要求终止该进程的信号，
// 或者是需要调用一个信号句柄(信号处理程序)。如果pid所指向的子进程早已退出(已成所谓的僵死进程)，
// 则本调用将立刻返回。子进程使用的所有资源将释放。
// 如果pid > 0，表示等待进程号等于pid的子进程。
// 如果pid = 0, 表示等待进程组号等于当前进程组号的任何子进程。
// 如果pid < -1,表示等待进程组号等于pid绝对值的任何子进程。
// 如果pid = -1,表示等待任何子进程。
// 如 options = WUNTRACED,表示如果子进程是停止的，也马上返回(无须跟踪)
// 若 options = WNOHANG, 表示如果没有子进程退出或终止就马上返回。
// 如果返回状态指针 stat_addr不为空，则就将状态信息保存到那里。
// 参数pid是进程号，*stat_addr是保存状态信息位置的指针，options是waitpid选项。
int sys_waitpid(pid_t pid,unsigned long * stat_addr, int options)
{
	int flag, code;             // flag标志用于后面表示所选出的子进程处于就绪或睡眠态。
	struct task_struct ** p;

	verify_area(stat_addr,4);
repeat:
	flag=0;
    // 从任务数组末端开始扫描所有任务，跳过空项、本进程项以及非当前进程的子进程项。
	for(p = &LAST_TASK ; p > &FIRST_TASK ; --p) {
		if (!*p || *p == current)
			continue;
		if ((*p)->father != current->pid)
			continue;
        // 此时扫描选择到的进程p肯定是当前进程的子进程。
        // 如果等待的子进程号pid>0，但与被扫描子进程p的pid不相等，说明它是当前进程另外的
        // 子进程，于是跳过该进程，接着扫描下一个进程。
		if (pid>0) {
			if ((*p)->pid != pid)
				continue;
        // 否则，如果指定等待进程的pid=0,表示正在等待进程组号等于当前进程组号的任何子进程。
        // 如果此时被扫描进程p的进程组号与当前进程的组号不等，则跳过。
		} else if (!pid) {
			if ((*p)->pgrp != current->pgrp)
				continue;
        // 否则，如果指定的pid < -1,表示正在等待进程组号等于pid绝对值的任何子进程。如果此时
        // 被扫描进程p的组号与pid的绝对值不等，则跳过。
		} else if (pid != -1) {
			if ((*p)->pgrp != -pid)
				continue;
		}
        // 如果前3个对pid的判断都不符合，则表示当前进程正在等待其任何子进程，也即pid=-1的情况，
        // 此时所选择到的进程p或者是其进程号等于指定pid，或者是当前进程组中的任何子进程，或者
        // 是进程号等于指定pid绝对值的子进程，或者是任何子进程(此时指定的pid等于-1).接下来根据
        // 这个子进程p所处的状态来处理。
		switch ((*p)->state) {
            // 子进程p处于停止状态时，如果此时WUNTRACED标志没有置位，表示程序无须立刻返回，于是
            // 继续扫描处理其他进程。如果WUNTRACED置位，则把状态信息0x7f放入*stat_addr，并立刻
            // 返回子进程号pid.这里0x7f表示的返回状态是wifstopped（）宏为真。
			case TASK_STOPPED:
				if (!(options & WUNTRACED))
					continue;
				put_fs_long(0x7f,stat_addr);
				return (*p)->pid;
            // 如果子进程p处于僵死状态，则首先把它在用户态和内核态运行的时间分别累计到当前进程
            // (父进程)中，然后取出子进程的pid和退出码，并释放该子进程。最后返回子进程的退出码和pid.
			case TASK_ZOMBIE:
				current->cutime += (*p)->utime;
				current->cstime += (*p)->stime;
				flag = (*p)->pid;                   // 临时保存子进程pid
				code = (*p)->exit_code;             // 取子进程的退出码
				release(*p);                        // 释放该子进程
				put_fs_long(code,stat_addr);        // 置状态信息为退出码值
				return flag;                        // 返回子进程的pid
            // 如果这个子进程p的状态既不是停止也不是僵死，那么就置flag=1,表示找到过一个符合
            // 要求的子进程，但是它处于运行态或睡眠态。
			default:
				flag=1;
				continue;
		}
	}
    // 在上面对任务数组扫描结束后，如果flag被置位，说明有符合等待要求的子进程并没有处于退出或
    // 僵死状态。如果此时已设置WNOHANG选项(表示若没有子进程处于退出或终止态就立刻返回)，就
    // 立刻返回0，退出。否则把当前进程置为可中断等待状态并重新执行调度。当又开始执行本进程时，
    // 如果本进程没有收到除SIGCHLD以外的信号，则还是重复处理。否则，返回出错码‘中断系统调用’
    // 并退出。针对这个出错号用户程序应该再继续调用本函数等待子进程。
	if (flag) {
		if (options & WNOHANG)                  // options = WNOHANG,则立刻返回。
			return 0;
		current->state=TASK_INTERRUPTIBLE;      // 置当前进程为可中断等待态
		schedule();                             // 重新调度。
		if (!(current->signal &= ~(1<<(SIGCHLD-1))))
			goto repeat;
		else
			return -EINTR;                      // 返回出错码(中断的系统调用)
	}
    // 若没有找到符合要求的子进程，则返回出错码(子进程不存在)。
	return -ECHILD;
}


