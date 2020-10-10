#define move_to_user_mode() \
__asm__ ("movl %%esp,%%eax\n\t" \	//tsz: #course 手动压栈，压了ss,esp,eflags,cs,eip,因为CPU压栈只能发生从3翻到0特权，因为要变成3特权，只能手动压栈
	// tsz: #personal AT&T汇编格式，dest在后面
	"pushl $0x17\n\t" \
	"pushl %%eax\n\t" \
	"pushfl\n\t" \
	"pushl $0x0f\n\t" \
	"pushl $1f\n\t" \	//tsz: #course 标号， f表示后面的1，b表示前面的1
	"iret\n" \	//tsz: #course ret是普通函数返回，iret是中断返回，后面开始交给进程0，因为task指针数组、ltr、lldt都指向进程0(在sched.c的sched_init函数中)(同时此时task中也只有task0)，（说明进程0是3特权）
		//tsz: #course 从此开始可以开始调度了，因为必要的中断都设置完成了
		// tsz: #course #think iret返回并不一定就能反转特权，看trap.c中的trap_init
	"1:\tmovl $0x17,%%eax\n\t" \	//tsz: #course 从这开始是进程0的用户态
	"movw %%ax,%%ds\n\t" \
	"movw %%ax,%%es\n\t" \
	"movw %%ax,%%fs\n\t" \
	"movw %%ax,%%gs" \
	:::"ax")

#define sti() __asm__ ("sti"::)
#define cli() __asm__ ("cli"::)
#define nop() __asm__ ("nop"::)

#define iret() __asm__ ("iret"::)

#define _set_gate(gate_addr,type,dpl,addr) \	// tsz: #book gate_addr已经从项数转变成了地址，type是15，dpl是0
__asm__ ("movw %%dx,%%ax\n\t" \	// tsz: #personal gcc内联汇编
	"movw %0,%%dx\n\t" \	//tsz: #course 0 1 2分别对应下面的i o o行
	"movl %%eax,%1\n\t" \
	"movl %%edx,%2" \
	: \	// tsz: #book 这里放输出，下面冒号后面放输入
	: "i" ((short) (0x8000+(dpl<<13)+(type<<8))), \	// tsz: #book i代表立即数，这里的8是用来使得存在位置1
	"o" (*((char *) (gate_addr))), \	// tsz: #book o代表内存地址，这是idt描述符前32bit的地址
	"o" (*(4+(char *) (gate_addr))), \	// tsz: #book idt描述符后32bit的地址
	"d" ((char *) (addr)),"a" (0x00080000))	// tsz: #book 分别对应edx与eax，前2B是用来赋值给段选择子的，8意味着内核特权，内核代码段

#define set_intr_gate(n,addr) \
	_set_gate(&idt[n],14,0,addr)

#define set_trap_gate(n,addr) \
	_set_gate(&idt[n],15,0,addr)

#define set_system_gate(n,addr) \
	_set_gate(&idt[n],15,3,addr)

#define _set_seg_desc(gate_addr,type,dpl,base,limit) {\
	*(gate_addr) = ((base) & 0xff000000) | \
		(((base) & 0x00ff0000)>>16) | \
		((limit) & 0xf0000) | \
		((dpl)<<13) | \
		(0x00408000) | \
		((type)<<8); \
	*((gate_addr)+1) = (((base) & 0x0000ffff)<<16) | \
		((limit) & 0x0ffff); }

#define _set_tssldt_desc(n,addr,type) \
__asm__ ("movw $104,%1\n\t" \
	"movw %%ax,%2\n\t" \
	"rorl $16,%%eax\n\t" \
	"movb %%al,%3\n\t" \
	"movb $" type ",%4\n\t" \
	"movb $0x00,%5\n\t" \
	"movb %%ah,%6\n\t" \
	"rorl $16,%%eax" \
	::"a" (addr), "m" (*(n)), "m" (*(n+2)), "m" (*(n+4)), \
	 "m" (*(n+5)), "m" (*(n+6)), "m" (*(n+7)) \
	)

#define set_tss_desc(n,addr) _set_tssldt_desc(((char *) (n)),((int)(addr)),"0x89")
#define set_ldt_desc(n,addr) _set_tssldt_desc(((char *) (n)),((int)(addr)),"0x82")

