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

//47、为什么get_free_page（）将新分配的页面清0？P265
//
//答：
//
//因为无法预知这页内存的用途，如果用作页表，不清零就有垃圾值，就是隐患。
//
//答2：Linux在回收页面时并没有将页面清0，只是将mem_map中与该页对应的位置0。在使用get_free_page申请页时，也是遍历mem_map寻找对应位为0的页，但是该页可能存在垃圾数据，如果不清0的话，若将该页用做页表，则可能导致错误的映射，引发错误，所以要将新分配的页面清0。
//
// 
//
//48、内核和普通用户进程并不在一个线性地址空间内，为什么仍然能够访问普通用户进程的页面？P271
//
//答：
//
//内核的线性地址空间和用户进程不一样，内核是不能通过跨越线性地址访问进程的，但由于早就占有了所有的页面，而且特权级是0，所以内核执行时，可以对所有的内容进行改动，“等价于”可以操作所有进程所在的页面。
//
// 
//
//49、详细分析一个进程从创建、加载程序、执行、退出的全过程。P273
//
//答：
//
//1.      创建进程，调用fork函数。
//
//a) 准备阶段，为进程在task[64]找到空闲位置，即find_empty_process（）；
//
//b) 为进程管理结构找到储存空间：task_struct和内核栈。
//
//c) 父进程为子进程复制task_struct结构
//
//d) 复制新进程的页表并设置其对应的页目录项
//
//e) 分段和分页以及文件继承。
//
//f)  建立新进程与全局描述符表（GDT）的关联
//
//g) 将新进程设为就绪态
//
//2.      加载进程
//
//a) 检查参数和外部环境变量和可执行文件
//
//b) 释放进程的页表
//
//c) 重新设置进程的程序代码段和数据段
//
//d) 调整进程的task_struct
//
//3.      进程运行
//
//a) 产生缺页中断并由操作系统响应
//
//b) 为进程申请一个内存页面
//
//c) 将程序代码加载到新分配的页面中
//
//d) 将物理内存地址与线性地址空间对应起来
//
//e) 不断通过缺页中断加载进程的全部内容
//
//f)  运行时如果进程内存不足继续产生缺页中断，
//
//4.      进程退出
//
//a) 进程先处理退出事务
//
//b) 释放进程所占页面
//
//c) 解除进程与文件有关的内容并给父进程发信号
//
//d) 进程退出后执行进程调度
//
// 
//
//50、详细分析多个进程（无父子关系）共享一个可执行程序的完整过程。
//
//答：
//
//假设有三个进程A、B、C，进程A先执行，之后是B最后是C，它们没有父子关系。A进程启动后会调用open函数打开该可执行文件，然后调用sys_read()函数读取文件内容,该函数最终会调用bread函数，该函数会分配缓冲块，进行设备到缓冲块的数据交换，因为此时为设备读入，时间较长，所以会给该缓冲块加锁，调用sleep_on函数，A进程被挂起，调用schedule()函数B进程开始执行。
//
//B进程也首先执行open（）函数，虽然A和B打开的是相同的文件，但是彼此操作没有关系，所以B继承需要另外一套文件管理信息，通过open_namei()函数。B进程调用read函数，同样会调用bread（），由于此时内核检测到B进程需要读的数据已经进入缓冲区中，则直接返回，但是由于此时设备读没有完成，缓冲块以备加锁，所以B将因为等待而被系统挂起，之后调用schedule()函数。
//
//C进程开始执行，但是同B一样，被系统挂起，调用schedule()函数，假设此时无其它进程，则系统0进程开始执行。
//
//假设此时读操作完成，外设产生中断，中断服务程序开始工作。它给读取的文件缓冲区解锁并调用wake_up()函数，传递的参数是&bh->b_wait,该函数首先将C唤醒，此后中断服务程序结束，开始进程调度，此时C就绪，C程序开始执行，首先将B进程设为就绪态。C执行结束或者C的时间片削减为0时，切换到B进程执行。进程B也在sleep_on()函数中，调用schedule函数进程进程切换，B最终回到sleep_on函数，进程B开始执行，首先将进程A设为就绪态，同理当B执行完或者时间片削减为0时，切换到A执行，此时A的内核栈中tmp对应NULL，不会再唤醒进程了。
//
//另一种答案：
//
//依次创建3个用户进程，每个进程都有自己的task。假设进程1先执行，需要压栈产生缺页中断，内核为其申请空闲物理页面，并映射到进程1的线性地址空间。这时产生时钟中断，轮到进程2执行，进程2也执行同样逻辑的程序。之后，又轮到进程3执行，也是压栈，并设置text。可见，三个进程虽程序相同，但数据独立，用TSS和LDT实现对进程的保护。
//
// 
//
//51、缺页中断是如何产生的，页写保护中断是如何产生的，操作系统是如何处理的？P264,268-270
//
//答：
//
//① 缺页中断产生 P264
//
//每一个页目录项或页表项的最后3位，标志着所管理的页面的属性，分别是U/S,R/W,P.如果和一个页面建立了映射关系，P标志就设置为1，如果没有建立映射关系，则P位为0。进程执行时，线性地址被MMU即系，如果解析出某个表项的P位为0，就说明没有对应页面，此时就会产生缺页中断。操作系统会调用_do_no_page为进程申请空闲页面，将程序加载到新分配的页面中，并建立页目录表-页表-页面的三级映射管理关系。
//
//② 页写保护中断 P268-270
//
//假设两个进程共享一个页面，该页面处于写保护状态即只读，此时若某一进程执行写操作，就会产生“页写保护”异常。操作系统会调用_do_wp_page，采用写时复制的策略，为该进程申请空闲页面，将该进程的页表指向新申请的页面，然后将原页表的数据复制到新页面中，同时将原页面的引用计数减1。该进程得到自己的页面，就可以执行写操作。
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


//52、为什么要设计缓冲区，有什么好处？
//
//答：
//
//缓冲区的作用主要体现在两方面：
//
//① 形成所有块设备数据的统一集散地，操作系统的设计更方便，更灵活；
//
//② 数据块复用，提高对块设备文件操作的运行效率。在计算机中，内存间的数据交换速度是内存与硬盘数据交换速度的2个量级，如果某个进程将硬盘数据读到缓冲区之后，其他进程刚好也需要读取这些数据，那么就可以直接从缓冲区中读取，比直接从硬盘读取快很多。如果缓冲区的数据能够被更多进程共享的话，计算机的整体效率就会大大提高。同样，写操作类似。
//
// 
//
//53、操作系统如何利用buffer_head中的 b_data，b_blocknr，b_dev，b_uptodate，b_dirt，b_count，b_lock，b_wait管理缓冲块的？
//
//答：
//
//buffer_head负责进程与缓冲块的数据交互，让数据在缓冲区中停留的时间尽可能长。
//
//b_data指向缓冲块，用于找到缓冲块的位置。
//
//进程与缓冲区及缓冲区与硬盘之间都是以缓冲块为单位进行数据交互的，而b_blocknr，b_dev唯一标识一个块，用于保证数据交换的正确性。另外缓冲区中的数据被越多进程共享，效率就越高，因此要让缓冲区中的数据块停留的时间尽可能久，而这正是由b_blocknr，b_dev决定的，内核在hash表中搜索缓冲块时，只看设备号与块号，只要缓冲块与硬盘数据的绑定关系还在，就认定数据块仍停留在缓冲块中，就可以直接用。
//
//b_uptodate与b_dirt，是为了解决缓冲块与数据块的数据正确性问题而存在的。b_uptodate针对进程方向，如果b_uptodate为1，说明缓冲块的数据已经是数据块中最新的，可以支持进程共享缓冲块中的数据；如果b_uptodate为0，提醒内核缓冲块并没有用绑定的数据块中的数据更新，不支持进程共享该缓冲块。
//
//b_dirt是针对硬盘方向的，b_dirt为1说明缓冲块的内容被进程方向的数据改写了，最终需要同步到硬盘上；b_dirt为0则说明不需要同步
//
//b_count记录每个缓冲块有多少进程共享。 b_count大于0表明有进程在共享该缓冲块，当进程不需要共享缓冲块时，内核会解除该进程与缓冲块的关系，并将b_count数值减1，为0表明可以被当作新缓冲块来申请使用。
//
//b_lock为1说明缓冲块正与硬盘交互，内核会拦截进程对该缓冲块的操作，以免发生错误，交互完成后，置0表明进程可以操作该缓冲块。
//
//b_wait记录等待缓冲块的解锁而被挂起的进程，指向等待队列前面进程的task_struct。
//
//54、copy_mem（）和copy_page_tables（）在第一次调用时是如何运行的？
//答：copy_mem()的第一次调用是进程0创建进程1时，它先提取当前进程（进程0）的代码段、数据段的段限长，并将当前进程（进程0）的段限长赋值给子进程（进程1）的段限长。然后提取当前进程（进程0）的代码段、数据段的段基址，检查当前进程（进程0）的段基址、段限长是否有问题。接着设置子进程（进程1）的LDT段描述符中代码段和数据段的基地址为nr(1)*64MB。最后调用copy_page_table()函数
//
//copy_page_table()的参数是源地址、目的地址和大小，首先检测源地址和目的地址是否都是4MB的整数倍，如不是则报错，不符合分页要求。然后取源地址和目的地址所对应的页目录项地址，检测如目的地址所对应的页目录表项已被使用则报错，其中源地址不一定是连续使用的，所以有不存在的跳过。接着，取源地址的页表地址，并为目的地址申请一个新页作为子进程的页表，且修改为已使用。然后，判断是否源地址为0，即父进程是否为进程0 ，如果是，则复制页表项数为160，否则为1k。最后将源页表项复制给目的页表，其中将目的页表项内的页设为“只读”，源页表项内的页地址超过1M的部分也设为"只读"（由于是第一次调用，所以父进程是0，都在1M内，所以都不设为“只读”），并在mem_map中所对应的项引用计数加1。1M内的内核区不参与用户分页管理。
//
// 
//
//55、 用图表示下面的几种情况，并从代码中找到证据：
//A当进程获得第一个缓冲块的时候，hash表的状态
//
//B经过一段时间的运行。已经有2000多个buffer_head挂到hash_table上时，hash表（包括所有的buffer_head）的整体运行状态。
//
//C经过一段时间的运行，有的缓冲块已经没有进程使用了（空闲），这样的空闲缓冲块是否会从hash_table上脱钩？
//
//D经过一段时间的运行，所有的buffer_head都挂到hash_table上了，这时，又有进程申请空闲缓冲块，将会发生什么？
//
//A
//
//getblk(int dev, int block) à get_hash_table(dev,block) -> find_buffer(dev,block) -> hash(dev, block)
//
//哈希策略为：
//
//              #define _hashfn(dev,block)(((unsigned)(dev block))%NR_HASH)
//
//              #define hash(dev,block) hash_table[_hashfn(dev, block)]
//
//此时，dev为0x300，block为0，NR_HASH为307，哈希结果为154，将此块插入哈希表中次位置后
//
//
//B
//
////代码路径 ：fs/buffer.c:   
//
//…
//
//static inline void insert_into_queues(struct buffer_head * bh) {
//
///*put at end of free list */   
//
//bh->b_next_free= free_list;   
//
//bh->b_prev_free= free_list->b_prev_free;   
//
//free_list->b_prev_free->b_next_free= bh;   
//
//free_list->b_prev_free= bh;
//
///*put the buffer in new hash-queue if it has a device */   
//
//bh->b_prev= NULL;   
//
//bh->b_next= NULL;   
//
//if (!bh->b_dev)        
//
//return;  
//
//bh->b_next= hash(bh->b_dev,bh->b_blocknr);   
//
//hash(bh->b_dev,bh->b_blocknr)= bh;   
//
//bh->b_next->b_prev= bh
//
//       }
//
//C
//
//不会脱钩，会调用brelse()函数，其中if(!(buf->b_count--))，计数器减一。没有对该缓冲块执行remove操作。由于硬盘读写开销一般比内存大几个数量级，因此该空闲缓冲块若是能够再次被访问到，对提升性能是有益的。
//
//D
//
//进程顺着freelist找到没被占用的，未被上锁的干净的缓冲块后，将其引用计数置为1，然后从hash队列和空闲块链表中移除该bh，然后根据此新的设备号和块号重新插入空闲表和哈西队列新位置处，最终返回缓冲头指针。
//
//Bh->b_count=1;
//
//Bh->b_dirt=0;
//
//Bh->b_uptodate=0;
//
//Remove_from_queues(bh);
//
//Bh->b_dev=dev;
//
//Bh->b_blocknr=block;
//
//Insert_into_queues(bh);
//
//56、 Rd_load()执行完之后，虚拟盘已经成为可用的块设备，并成为根设备。在向虚拟盘中copy任何数据之前，虚拟盘中是否有引导快、超级快、i节点位图、逻辑块位图、i节点、逻辑块？
//虚拟盘中没有引导快、超级快、i节点位图、逻辑块位图、i节点、逻辑块。在rd_load()函数中的memcpy(cp, bh->b_data,BLOCK_SIZE)执行以前，对虚拟盘的操作仅限于为虚拟盘分配2M的内存空间，并将虚拟盘的所有内存区域初始化为0.所以虚拟盘中并没有数据，仅是一段被’\0’填充的内存空间。
//
//（代码路径：kernel/blk_dev/ramdisk.c   rd_load:）
//
//Rd_start = (char *)mem_start;
//
//Rd_length = length;
//
//Cp = rd_start;
//
//For (i=0; i<length; i++)
//
//       *cp++=’\0\;
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

//57、 在虚拟盘被设置为根设备之前，操作系统的根设备是软盘，请说明设置软盘为根设备的技术路线。
//答：首先，将软盘的第一个山区设置为可引导扇区:
//
//（代码路径：boot/bootsect.s）                         boot_flag: .word 0xAA55
//
//在主Makefile文件中设置ROOT_DEV=/dev/hd6。并且在bootsect.s中的508和509处设置ROOT_DEV=0x306；在tools/build中根据Makefile中的ROOT_DEV设置MAJOR_TOOT和MINOR_ROOT，并将其填充在偏移量为508和509处：
//
//(代码路径：Makefile)                 tools/build boot/bootsect boot/setup tools/system $(ROOT_DEV) > Image
//
//随后被移至0x90000+508(即0x901FC)处，最终在main.c中设置为ORIG_ROOT_DEV并将其赋给ROOT_DEV变量：
//
//(代码路径：init/main.c)                    
//
//62 #define ORIG_ROOT_DEV (*(unsigned short *)0x901FC)
//
//113 ROOT_DEV = ORIG_ROOT_DEV;
//
// 
//
//58、 Linux0.11是怎么将根设备从软盘更换为虚拟盘，并加载了根文件系统？
//rd_load函数从软盘读取文件系统并将其复制到虚拟盘中并通过设置ROOT_DEV为0x0101将根设备从软盘更换为虚拟盘，然后调用mount_root函数加载跟文件系统，过程如下：初始化file_table和super_block，初始化super_block并读取根i节点，然后统计空闲逻辑块数及空闲i节点数：
//
//(代码路径：kernel/blk_drv/ramdisk.c:rd_load)          ROOT_DEV=0x0101;
//
//主设备好是1，代表内存，即将内存虚拟盘设置为根目录。
//
// 
//
//59、add_request()函数中有下列代码
//
// 
//
//         \linux0.11\kernel\blk_drv\ll_rw_blk.c
//
//         if (!(tmp = dev->current_request)) {
//
//                   dev->current_request = req;
//
//                   sti();
//
//                   (dev->request_fn)();
//
//                   return;
//
//         }
//
//其中的
//
// 
//
//         if (!(tmp = dev->current_request)) {
//
//                   dev->current_request = req;
//
//         }
//
//是什么意思？(P322)
//
// 
//
//答：查看指定设备是否有当前请求项，即查看设备是否忙。如果指定设备dev当前请求项（dev->current_request ==NULL） 为空，则表示目前设备没有请求项，本次是第1个请求项，也是唯一的一个。因此可将块设备当前请求指针直接指向该请求项，并立即执行相应设备的请求函数。
//
// 
//
//60、 read_intr()函数中，下列代码是什么意思？为什么这样做？(P323)
//
// 
//
//         \linux0.11\kernel\blk_drv\hd.c
//
//         if (--CURRENT->nr_sectors) {
//
//                   do_hd = &read_intr;
//
//                   return;
//
//         }
//
//答：当读取扇区操作成功后，“—CURRENT->nr_sectors”将递减请求项所需读取的扇区数值。若递减后不等于0，表示本项请求还有数据没读完，于是再次置中断调用C函数指针“do_hd = &read_intr;”并直接返回，等待硬盘在读出另1扇区数据后发出中断并再次调用本函数。//// 程序退出处理函数。
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


