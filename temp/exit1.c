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

//17、在Linux操作系统中大量使用了中断、异常类的处理，究竟有什么好处？
//
//采用以“被动模式” 代替“主动轮询” 模式来处理终端问题。进程在主机中运算需用到 CPU，其中可能进行“异常处理” ，此时需要具体的服务程序来执行。 这种中断服务体系的建立是为了被动响应中断信号。因此， CPU 就可以更高效的处理用户程序服务， 不用考虑随机可能产生的中断信号，从而提高了操作系统的综合效率。
//
// 
//
//18、copy_process函数的参数最后五项是：long eip,long cs,long eflags,long esp,long ss。查看栈结构确实有这五个参数，奇怪的是其他参数的压栈代码都能找得到，确找不到这五个参数的压栈代码，反汇编代码中也查不到，请解释原因。
//
//在 fork()中， 当执行“int $0x80” 时产生一个软中断， 使 CPU 硬件自动将 SS、 ESP、EFLAGS、 CS、 EIP 这 5 个寄存器的数值按这个顺序压入进程 0 的内核栈。 硬件压栈可确保 eip 的值指向正确的指令， 使中断返回后程序能继续执行。因为通过栈进行函数传递参数，所以恰可做为 copy_process 的最后五项参数。
//
// 
//
//19、分析get_free_page()函数的代码，叙述在主内存中获取一个空闲页的技术路线。
//
//通过逆向扫描页表位图 mem_map， 并由第一空页的下标左移 12 位加 LOW_MEM 得到该页的物理地址， 位于 16M 内存末端。P89代码考试不用看
//
//过程：
//
//① 将EAX 设置为0,EDI 设置指向mem_map 的最后一项（mem_map+PAGING_PAGES-1），std设置扫描是从高地址向低地址。从mem_map的最后一项反向扫描，找出引用次数为0(AL)的页，如果没有则退出；如果找到，则将找到的页设引用数为1；
//
//② ECX左移12位得到页的相对地址，加LOW_MEM得到物理地址，将此页最后一个字节的地址赋值给EDI（LOW_MEM+4092）；
//
//③ stosl将EAX的值设置到ES:EDI所指内存，即反向清零1024*32bit，将此页清空；
//
//④ 将页的地址（存放在EAX）返回。
//
// 
//
//20、分析copy_page_tables（）函数的代码，叙述父进程如何为子进程复制页表。
//
//P97一段话解释
//
// 
//
//21、进程0创建进程1时，为进程1建立了task_struct及内核栈，第一个页表，分别位于物理内存16MB顶端倒数第一页、第二页。请问，这两个页究竟占用的是谁的线性地址空间，内核、进程0、进程1、还是没有占用任何线性地址空间？说明理由（可以图示）并给出代码证据。
//
//答：均占用内核的线性地址空间， 原因如下：
//通过逆向扫描页表位图，并由第一空页的下标左移 12 位加 LOW_MEM 得到该页的物理地址，位于 16M 内存末端。 代码如下
//
//unsigned long get_free_page(void)
//{register unsigned long __res asm("ax");
//__asm__("std ; repne ; scasb\n\t"
//"jne 1f\n\t"
//"movb $1,1(%%edi)\n\t"
//"sall $12,%%ecx\n\t"
//"addl %2,%%ecx\n\t"
//"movl %%ecx,%%edx\n\t"
//"movl $1024,%%ecx\n\t"
//"leal 4092(%%edx),%%edi\n\t"
//"rep ; stosl\n\t"
//" movl %%edx,%%eax\n"
//"1: cld"
//:"=a" (__res)
//:"0" (0),"i" (LOW_MEM),"c" (PAGING_PAGES),
//"D" (mem_map+PAGING_PAGES-1)
//);
//return __res;
//}
//
//进程 0 和进程 1 的 LDT 的 LIMIT 属性将进程 0 和进程 1 的地址空间限定0~640KB， 所以进程 0、 进程 1 均无法访问到这两个页面， 故两页面占用内核的线性地址空间。进程 0 的局部描述符如下
//
//include/linux/sched.h: INIT_TASK
///* ldt */ {0x9f,0xc0fa00}, \
//{0x9f,0xc0f200}, \
//内核线性地址等于物理地址(0x00000~0xfffff)， 挂接操作的代码如下(head.s/setup_paging)：
//movl $pg0+7,pg_dir /* set present bit/user r/w */
//movl $pg1+7,pg_dir+4 /* --------- " " --------- */
//movl $pg2+7,pg_dir+8 /* --------- " " --------- */
//movl $pg3+7,pg_dir+12 /* --------- " " --------- */
//movl $pg3+4092,%edi
//movl $0xfff007,%eax /* 16Mb - 4096 + 7 (r/w user,p) */
//std
//1: stosl /* fill pages backwards - more efficient :-) */
//subl $0x1000,%eax
//jge 1b
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


//22、假设：经过一段时间的运行，操作系统中已经有5个进程在运行，且内核分别为进程4、进程5分别创建了第一个页表，这两个页表在谁的线性地址空间？用图表示这两个页表在线性地址空间和物理地址空间的映射关系。
//
//内核的线性地址空间
//
//注：65 和 81 应该改成 64 和 80
//
// 
//
//23、#define switch_to(n) {\
//
//struct {long a,b;} __tmp; \
//
//__asm__("cmpl %%ecx,_current\n\t" \
//
//         "je 1f\n\t" \
//
//         "movw %%dx,%1\n\t" \
//
//         "xchgl %%ecx,_current\n\t" \
//
//         "ljmp %0\n\t" \
//
//         "cmpl %%ecx,_last_task_used_math\n\t" \
//
//         "jne 1f\n\t" \
//
//         "clts\n" \
//
//         "1:" \
//
//         ::"m" (*&__tmp.a),"m" (*&__tmp.b), \
//
//         "d" (_TSS(n)),"c" ((long) task[n])); \
//
//}
//
//代码中的"ljmp %0\n\t" 很奇怪，按理说jmp指令跳转到得位置应该是一条指令的地址，可是这行代码却跳到了"m" (*&__tmp.a)，这明明是一个数据的地址，更奇怪的，这行代码竟然能正确执行。请论述其中的道理。
//
//答：其中a对应EIP，b对应CS，ljmp此时通过CPU中的电路进行硬件切换，进程由当前进程切换到进程n。CPU将当前寄存器的值保存到当前进程的TSS中，将进程n的TSS数据及LDT的代码段和数据段描述符恢复给CPU的各个寄存器，实现任务切换。
//
// 
//
//24、进程0开始创建进程1，调用fork（），跟踪代码时我们发现，fork代码执行了两次，第一次，执行fork代码后，跳过init（）直接执行了for(;;) pause()，第二次执行fork代码后，执行了init（）。奇怪的是，我们在代码中并没有看到向转向fork的goto语句，也没有看到循环语句，是什么原因导致fork反复执行？请说明理由（可以图示），并给出代码证据。
//
//主要涉及的代码位置如下：
//
//Init/main.c 代码中P103 —— if 判断
//
//Include/unistd.h 中P102 —— fork函数代码
//
//进程1 TSS赋值，特别是 eip，eax 赋值
//
//copy_process:
//
//p->pid = last_pid;
//
//…
//
//p->tss.eip = eip;
//
//p->tss.eflags = eflags;
//
//p->tss.eax = 0;
//
//…
//
//p->tss.esp = esp;
//
//…
//
//p->tss.cs = cs & 0xffff;
//
//p->tss.ss = ss & 0xffff;
//
//…
//
//p->state = TASK_RUNNING;
//
//return last_pid;
//
//原因
//
//fork 为 inline 函数，其中调用了 sys_call0，产生 0x80 中断，将 ss, esp, eflags, cs, eip 压栈，其中 eip 为 int 0x80 的下一句的地址。在 copy_process 中，内核将进程 0 的 tss 复制得到进程 1 的 tss，并将进程 1 的 tss.eax 设为 0，而进程 0 中的 eax 为 1。在进程调度时 tss 中的值被恢复至相应寄存器中，包括 eip， eax 等。所以中断返回后，进程 0 和进程 1 均会从 int  0x80 的下一句开始执行，即 fork 执行了两次。
//
//由于 eax 代表返回值，所以进程 0 和进程 1 会得到不同的返回值，在fork返回到进程0后，进程0判断返回值非 0，因此执行代码for(;;) pause();
//
//在sys_pause函数中，内核设置了进程0的状态为 TASK_INTERRUPTIBLE，并进行进程调度。由于只有进程1处于就绪态，因此调度执行进程1的指令。由于进程1在TSS中设置了eip等寄存器的值，因此从 int 0x80 的下一条指令开始执行，且设定返回 eax 的值作为 fork 的返回值（值为 0），因此进程1执行了 init 的 函数。导致反复执行，主要是利用了两个系统调用 sys_fork 和 sys_pause 对进程状态的设置，以及利用了进程调度机制。
//
// 
//
//25、打开保护模式、分页后，线性地址到物理地址是如何转换的？
//
//答：保护模式下，每个线性地址为32位，MMU按照10-10-12的长度来识别线性地址的值。CR3中存储着页目录表的基址，线性地址的前10位表示页目录表中的页目录项，由此得到所在的页表地址。中间10位记录了页表中的页表项位置，由此得到页的位置，最后12位表示页内偏移。示意图（P97 图3-9线性地址到物理地址映射过程示意图）
//
// 
//
//26、getblk函 数中，申请空闲缓冲块的标准就是b_count为0，而申请到之后，为什么在wait_on_buffer(bh)后又执行if（bh->b_count）来判断b_count是否为0？
//
//P114参考，考试不用看
//
//wait_on_buffer(bh)内包含睡眠函数，虽然此时已经找到比较合适的空闲缓冲块，但是可能在睡眠阶段该缓冲区被其他任务所占用，因此必须重新搜索，判断是否被修改，修改则写盘等待解锁。判断若被占用则重新repeat，继续执行if（bh->b_count）
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

//27、b_dirt已经被置为1的缓冲块，同步前能够被进程继续读、写？给出代码证据。
//
//同步前能够被进程继续读、写
//
//b_uptodate设置为1后，内核就可以支持进程共享该缓冲块的数据了，读写都可以，读操作不会改变缓冲块的内容，所以不影响数据，而执行写操作后，就改变了缓冲块的内容，就要将b_dirt标志设置为1。由于此前缓冲块中的数据已经用硬盘数据块更新了，所以后续的同步未被改写的部分不受影响，同步是不更改缓冲块中数据的，所以b_uptodate仍为1。即进程在b_dirt置为1时，仍能对缓冲区数据进行读写。
//
//代码证据：代码P331
//
// 
//
//28、分析panic函数的源代码，根据你学过的操作系统知识，完整、准确的判断panic函数所起的作用。假如操作系统设计为支持内核进程（始终运行在0特权级的进程），你将如何改进panic函数？
//
//panic()函数是当系统发现无法继续运行下去的故障时将调用它，会导致程序终止，然后由系统显示错误号。如果出现错误的函数不是进程0，那么就要进行数据同步，把缓冲区中的数据尽量同步到硬盘上。遵循了Linux尽量简明的原则。
//
//改进panic函数：将死循环for(;;)；改进为跳转到内核进程（始终运行在0特权级的进程），让内核继续执行。
//
//代码： kernel/panic.c
//
//#include <linux/kernel.h>
//
//#include <linux/sched.h>
//
//void sys_sync(void);
//
//volatile void panic(const char * s)
//
//{
//
//         printk("Kernel panic: %s\n\r",s);
//
//         if (current == task[0])
//
//                   printk("In swapper task - not syncing\n\r");
//
//         else
//
//                   sys_sync();
//
//         for(;;);
//
//}
//
// 
//
//29、详细分析进程调度的全过程。考虑所有可能（signal、alarm除外）
//
//1. 进程中有就绪进程，且时间片没有用完。
//
//正常情况下，schedule()函数首先扫描任务数组。通过比较每个就绪（TASK_RUNNING）任务的运行时间递减滴答计数counter 的值来确定当前哪个进程运行的时间最少。哪一个的值大，就表示运行时间还不长，于是就选中该进程，最后调用switch_to()执行实际的进程切换操作
//
//2. 进程中有就绪进程，但所有就绪进程时间片都用完（c=0）
//
//如果此时所有处于TASK_RUNNING 状态进程的时间片都已经用完，系统就会根据每个进程的优先权值priority，对系统中所有进程（包括正在睡眠的进程）重新计算每个任务需要运行的时间片值counter。计算的公式是：
//
//counter = counter + priority/2
//
//然后 schdeule()函数重新扫描任务数组中所有处于TASK_RUNNING 状态，重复上述过程，直到选择出一个进程为止。最后调用switch_to()执行实际的进程切换操作。
//
//3. 所有进程都不是就绪的c=-1
//
//此时代码中的c=-1，next=0，跳出循环后，执行switch_to(0)，切换到进程0执行，因此所有进程都不是就绪的时候进程0执行。
//
// 
//
//30、wait_on_buffer函数中为什么不用if（）而是用while（）？
//
//答：因为可能存在一种情况是，很多进程都在等待一个缓冲块。在缓冲块同步完毕，唤醒各等待进程到轮转到某一进程的过程中，很有可能此时的缓冲块又被其它进程所占用，并被加上了锁。此时如果用if()，则此进程会从之前被挂起的地方继续执行，不会再判断是否缓冲块已被占用而直接使用，就会出现错误；而如果用while()，则此进程会再次确认缓冲块是否已被占用，在确认未被占用后，才会使用，这样就不会发生之前那样的错误。
//
// 
//
//31、操作系统如何利用b_uptodate保证缓冲块数据的正确性？new_block (int dev)函数新申请一个缓冲块后，并没有读盘，b_uptodate却被置1，是否会引起数据混乱？详细分析理由。
//
//答：b_uptodate是缓冲块中针对进程方向的标志位，它的作用是告诉内核，缓冲块的数据是否已是数据块中最新的。当b_update置1时，就说明缓冲块中的数据是基于硬盘数据块的，内核可以放心地支持进程与缓冲块进行数据交互；如果b_uptodate为0，就提醒内核缓冲块并没有用绑定的数据块中的数据更新，不支持进程共享该缓冲块。
//
//当为文件创建新数据块，新建一个缓冲块时，b_uptodate被置1，但并不会引起数据混乱。此时，新建的数据块只可能有两个用途，一个是存储文件内容，一个是存储文件的i_zone的间接块管理信息。
//
//如果是存储文件内容，由于新建数据块和新建硬盘数据块，此时都是垃圾数据，都不是硬盘所需要的，无所谓数据是否更新，结果“等效于”更新问题已经解决。
//
//如果是存储文件的间接块管理信息，必须清零，表示没有索引间接数据块，否则垃圾数据会导致索引错误，破坏文件操作的正确性。虽然缓冲块与硬盘数据块的数据不一致，但同样将b_uptodate置1不会有问题。
//
//综合以上考虑，设计者采用的策略是，只要为新建的数据块新申请了缓冲块，不管这个缓冲块将来用作什么，反正进程现在不需要里面的数据，干脆全部清零。这样不管与之绑定的数据块用来存储什么信息，都无所谓，将该缓冲块的b_uptodate字段设置为1，更新问题“等效于”已解决
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


