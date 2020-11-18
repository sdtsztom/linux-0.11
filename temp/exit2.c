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

//32、add_reques（）函数中有下列代码
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
//         if (!(tmp = dev->current_request)) {
//
//                   dev->current_request = req;
//
//是什么意思？
//
//检查设备是否正忙，若目前该设备没有请求项，本次是唯一一个请求，之前无链表，则将该设备当前请求项指针直接指向该请求项，作为链表的表头。
//
// 
//
//33、do_hd_request()函数中dev的含义始终一样吗？
//
//122 页 不一样。
//
//答： 不是一样的。 dev/=5 之前表示当前硬盘的逻辑盘号。 这行代码之后表示的实际的物理设备号。
//
//34、read_intr（）函数中，下列代码是什么意思？为什么这样做？
//
//         if (--CURRENT->nr_sectors) {
//
//                   do_hd = &read_intr;
//
//                   return;}
//
//    答案：参照P131
//
// 
//
//35、bread（）函数代码中为什么要做第二次if (bh->b_uptodate)判断？
//
//         if (bh->b_uptodate)
//
//                   return bh;
//
//         ll_rw_block(READ,bh);
//
//         wait_on_buffer(bh);
//
//         if (bh->b_uptodate)
//
//                   return bh;
//
//第一次从高速缓冲区中取出指定和设备和块号相符的缓冲块， 判断缓冲块数据是否有效， 有效则返回此块， 正当用。 如果该缓冲块数据无效（更新标志未置位） ， 则发出读设备数据块请求。
//第二次，等指定数据块被读入，并且缓冲区解锁，睡眠醒来之后，要重新判断缓冲块是否有效，如果缓冲区中数据有效，则返回缓冲区头指针退出。否则释放该缓冲区返回 NULL,退出。在等待过程中，数据可能已经发生了改变，所以要第二次判断。
//
// 
//
//36、getblk（）函数中，两次调用wait_on_buffer（）函数，两次的意思一样吗？
//
//代码在书上113和114
//
// 
//
//答： 一样。 都是等待缓冲块解锁。
//
//第一次调用是在， 已经找到一个比较合适的空闲缓冲块， 但是此块可能是加锁的， 于是等待
//
//该缓冲块解锁。
//
//第二次调用， 是找到一个缓冲块， 但是此块被修改过， 即是脏的， 还有其他进程在写或此块
//
//等待把数据同步到硬盘上， 写完要加锁， 所以此处的调用仍然是等待缓冲块解锁。
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


//37、getblk（）函数中
//
//         do {
//
//                   if (tmp->b_count)
//
//                            continue;
//
//                   if (!bh || BADNESS(tmp)<BADNESS(bh)) {
//
//                            bh = tmp;
//
//                            if (!BADNESS(tmp))
//
//                                     break;
//
//                   }
//
///* and repeat until we find something good */
//
//         } while ((tmp = tmp->b_next_free) != free_list);
//
//说明什么情况下执行continue、break。
//
//（P114代码）
//
//Continue：if (tmp->b_count)在判断缓冲块的引用计数，如果引用计数不为0，那么继续判断空闲队列中下一个缓冲块（即continue），直到遍历完。
//
//Break：如果有引用计数为0的块，那么判断空闲队列中那些引用计数为0 的块的badness，找到一个最小的，如果在寻找的过程中出现badness为0的块，那么就跳出循环（即break）。
//
//如果利用函数get_hash_table找到了能对应上设备号和块号的缓冲块，那么直接返回。
//
//如果找不到，那么就分为三种情况：
//
//1.所有的缓冲块b_count=0，缓冲块是新的。
//
//2.虽然有b_count=0，但是有数据脏了，未同步或者数据脏了正在同步加和既不脏又不加锁三种情况；
//
//3.所有的缓冲块都被引用，此时b_count非0，即为所有的缓冲块都被占用了。
//
//综合以上三点可知，如果缓冲块的b_count非0，则continue继续查找，知道找到b_count=0的缓冲块；如果获取空闲的缓冲块，而且既不加锁又不脏，此时break，停止查找。
//
// 
//
//38、make_request（）函数      
//
//         if (req < request) {
//
//                   if (rw_ahead) {
//
//                            unlock_buffer(bh);
//
//                            return;
//
//                   }
//
//                   sleep_on(&wait_for_request);
//
//                   goto repeat;
//
// 
//
//其中的sleep_on(&wait_for_request)是谁在等？等什么？
//
//这行代码是当前进程在等（如：进程1），在等空闲请求项。
//
//make_request()函数创建请求项并插入请求队列，执行if的内容说明没有找到空请求项：如果是超前的读写请求，因为是特殊情况则放弃请求直接释放缓冲区，否则是一般的读写操作，此时等待直到有空闲请求项，然后从repeat开始重新查看是否有空闲的请求项。
//
// 
//
//往年题补充：
//
//39、setup程序里的cli是为了什么？
//答：cli为关中断，以为着程序在接下来的执行过程中，无论是否发生中断，系统都不再对此中断进行响应。
//
//因为在setup中，需要将位于 0x10000 的内核程序复制到 0x0000 处，bios中断向量表覆盖掉了，若此时如果产生中断，这将破坏原有的中断机制会发生不可预知的错误，所以要禁示中断。
//
// 
//
//40、打开A20和打开pe究竟是什么关系，保护模式不就是32位的吗？为什么还要打开A20？有必要吗？
//
//答：
//
//有必要。
//
//A20是CPU的第 21 位地址线，A20 未打开的时候，实模式下的最大寻址为 1MB+64KB,而第21根地址线被强制为0，所以相当于CPU“回滚”到内存地址起始处寻址。打开A20仅仅意味着CPU可以进行32位寻址，且最大寻址空间是4GB，而打开PE是使能保护模式。打开A20是打开PE的必要条件；而打开A20不一定非得打开PE。打开PE是说明系统处于保护模式下，如果不打开A20的话，A20 会被强制置 0，则保护模式下访问的内存是不连续的，如 0~1M,2~3M,4~5M 等，若要真正在保护模式下工作，必须打开A20，实现32位寻址。
//
// 
//
//41、Linux是用C语言写的，为什么没有从main还是开始，而是先运行3个汇编程序，道理何在？
//
//答：
//
//main 函数运行在 32 位的保护模式下，但系统启动时默认为 16 位的实模式，开机时的 16 位实模式与 main 函数执行需要的 32 位保护模式之间有很大的差距，这个差距需要由 3 个汇编程序来填补。其中 bootsect 负责加载， setup 与 head 则负责获取硬件参数，准备 idt,gdt,开启 A20， PE,PG，废弃旧的 16 位中断响应机制，建立新的 32 为 IDT，设置分页机制等。这些工作做完后，计算机处在32 位的保护模式状态下时，调用main的条件才算准备完毕。
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

//42、为什么static inline _syscall0(type,name)中需要加上关键字inline？
//
//答：
//
//因为_syscall0(int,fork)展开是一个真函数，普通真函数调用事需要将eip入栈，返回时需要讲eip出栈。inline是内联函数，它将标明为inline的函数代码放在符号表中，而此处的fork函数需要调用两次，加上inline后先进行词法分析、语法分析正确后就地展开函数，不需要有普通函数的call\ret等指令，也不需要保持栈的eip，效率很高。若不加上inline，第一次调用fork结束时将eip 出栈，第二次调用返回的eip出栈值将是一个错误值。
//
//答案2：inline一般是用于定义内联函数，内联函数结合了函数以及宏的优点，在定义时和函数一样，编译器会对其参数进行检查；在使用时和宏类似，内联函数的代码会被直接嵌入在它被调用的地方，这样省去了函数调用时的一些额外开销，比如保存和恢复函数返回地址等，可以加快速度。
//
// 
//
//43、根据代码详细说明copy_process函数的所有参数是如何形成的？
//
//答：
//
//long eip, long cs, long eflags, long esp, long ss；这五个参数是中断使CPU自动压栈的。
//
//long ebx, long ecx, long edx, long fs, long es, long ds为__system_call压进栈的参数。
//
//long none 为__system_call调用__sys_fork压进栈EIP的值。
//
//Int nr, long ebp, long edi, long esi, long gs,为__system_call压进栈的值。
//
//额外注释：
//
//一般在应用程序中，一个函数的参数是由函数定义的，而在操作系统底层中，函数参数可以由函数定义以外的程序通过压栈的方式“做”出来。copy_process函数的所有参数正是通过压栈形成的。代码见P83页、P85页、P86页。
//
// 
//
//44、根据代码详细分析，进程0如何根据调度第一次切换到进程1的？（P103-107）
//
//答：
//
//① 进程0通过fork函数创建进程1，使其处在就绪态。
//
//② 进程0调用pause函数。pause函数通过int 0x80中断，映射到sys_pause函数，将自身设为可中断等待状态，调用schedule函数。
//
//③ schedule函数分析到当前有必要进行进程调度，第一次遍历进程，只要地址指针不为为空，就要针对处理。第二次遍历所有进程，比较进程的状态和时间骗，找出处在就绪态且counter最大的进程，此时只有进程0和1，且进程0是可中断等待状态，只有进程1是就绪态，所以切换到进程1去执行。
//
// 
//
//45、进程0创建进程1时调用copy_process函数，在其中直接、间接调用了两次get_free_page函数，在物理内存中获得了两个页，分别用作什么？是怎么设置的？给出代码证据。
//
//答：
//
//第一次调用get_free_page函数申请的空闲页面用于进程1 的task_struct及内核栈。首先将申请到的页面清0，然后复制进程0的task_struct，再针对进程1作个性化设置，其中esp0 的设置，意味着设置该页末尾为进程 1 的堆栈的起始地址。代码见P90 及 P92。
//
//kenel/fork.c:copy_process
//
//p = (struct task_struct *)get_free_page();
//
//*p = *current
//
//p->tss.esp0 = PAGE_SIZE + (long)p;
//
//第二次调用get_free_page函数申请的空闲页面用于进程1的页表。在创建进程1执行copy_process中，执行copy_mem(nr,p)时，内核为进程1拷贝了进程 0的页表（160 项），同时修改了页表项的属性为只读。代码见P98。
//
//mm/memory.c: copy_page_table
//
//if(!(to_page_table = (unsigned long *)get_free_page()))
//
//         return -1;
//
//*to_dir = ((unsigned long)to_page_table) | 7;
//
// 
//
//46、用户进程自己设计一套LDT表，并与GDT挂接，是否可行，为什么？
//
//答：
//
//不可行
//
//GDT和LDT放在内核数据区，属于0特权级，3特权级的用户进程无权访问修改。此外，如果用户进程可以自己设计LDT的话，表明用户进程可以访问其他进程的LDT，则会削弱进程之间的保护边界，容易引发问题。
//
//补充：
//
//如果仅仅是形式上做一套和GDT，LDT一样的数据结构是可以的。但是真正其作用的GDT、LDT是CPU硬件认定的，这两个数据结构的首地址必须挂载在CPU中的GDTR、LDTR上，运行时CPU只认GDTR和LDTR指向的数据结构。而对GDTR和LDTR的设置只能在0特权级别下执行,3特权级别下无法把这套结构挂接在CR3上。
//
//LDT表只是一段内存区域，我们可以构造出用户空间的LDT。而且Ring0代码可以访问Ring3数据。但是这并代表我们的用户空间LDT可以被挂载到GDT上。考察挂接函数set_ldt_desc：1）它是Ring0代码，用户空间程序不能直接调用；2）该函数第一个参数是gdt地址，这是Ring3代码无权访问的，又因为gdt 很可能不在用户进程地址空间，就算有权限也是没有办法寻址的。3）加载ldt所用到的特权指令lldt也不是Ring3代码可以任意使用的。
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


