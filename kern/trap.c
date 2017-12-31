#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	extern void routine_divide();
	extern void routine_debug();
	extern void routine_nmi();
	extern void routine_brkpt();
	extern void routine_oflow();
	extern void routine_bound();
	extern void routine_illop();
	extern void routine_device();
	extern void routine_dblflt();
	extern void routine_tss();
	extern void routine_segnp();
	extern void routine_stack();
	extern void routine_gpflt();
	extern void routine_pgflt();
	extern void routine_fperr();
	extern void routine_align();
	extern void routine_mchk();
	extern void routine_simderr();
	extern void routine_syscall(); 

        extern void irq_timer();
	extern void irq_kbd();
	extern void irq_serial();
	extern void irq_spurious();
	extern void irq_ide();
	extern void irq_error();
	// SETGATE(gate, istrap, sel, off, dpl)	defined in inc/mmu.h，对传入的Gatedesc结构体进行初始化
	// gate：传入的Gatedesc结构
	// istrap：该中断位trap还是interrupt
	// sel：代码段的段地址
	// off：代码段偏移地址
	// dpl：优先级
	SETGATE(idt[T_DIVIDE],0,GD_KT,routine_divide,0);
	SETGATE(idt[T_DEBUG],0,GD_KT,routine_debug,0);
	SETGATE(idt[T_NMI],1,GD_KT,routine_nmi,0);
	SETGATE(idt[T_BRKPT],0,GD_KT,routine_brkpt,3);
	SETGATE(idt[T_OFLOW],0,GD_KT,routine_oflow,0);
	SETGATE(idt[T_BOUND],0,GD_KT,routine_bound,0);
	SETGATE(idt[T_ILLOP],0,GD_KT,routine_illop,0);
	SETGATE(idt[T_DEVICE],0,GD_KT,routine_device,0);
	SETGATE(idt[T_DBLFLT],0,GD_KT,routine_dblflt,0);
	SETGATE(idt[T_TSS],0,GD_KT,routine_tss,0); 
	SETGATE(idt[T_SEGNP],0,GD_KT,routine_segnp,0);
	SETGATE(idt[T_STACK],0,GD_KT,routine_stack,0);
	SETGATE(idt[T_GPFLT],0,GD_KT,routine_gpflt,0);
	SETGATE(idt[T_PGFLT],0,GD_KT,routine_pgflt,0);
	SETGATE(idt[T_FPERR],0,GD_KT,routine_fperr,0);
	SETGATE(idt[T_ALIGN],0,GD_KT,routine_align,0);
	SETGATE(idt[T_MCHK],0,GD_KT,routine_mchk,0); 
	SETGATE(idt[T_SIMDERR],0,GD_KT,routine_simderr,0);
	SETGATE(idt[T_SYSCALL],0,GD_KT,routine_syscall,3);
        //硬中断
	SETGATE(idt[IRQ_OFFSET+IRQ_TIMER],0,GD_KT,irq_timer,0);
	SETGATE(idt[IRQ_OFFSET+IRQ_KBD],0,GD_KT,irq_kbd,0);
	SETGATE(idt[IRQ_OFFSET+IRQ_SERIAL],0,GD_KT,irq_serial,0);
	SETGATE(idt[IRQ_OFFSET+IRQ_SPURIOUS],0,GD_KT,irq_spurious,0);
	SETGATE(idt[IRQ_OFFSET+IRQ_IDE],0,GD_KT,irq_ide,0);
	SETGATE(idt[IRQ_OFFSET+IRQ_ERROR],0,GD_KT,irq_error,0);
	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
// 初始化并加载per-CPU的TSS(Task State Segment)和IDT(中断描述表)
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct Cpu;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	// 这段代码在CPU0运行时是ok的，但是当在其他CPU下运行时会出错，因为
    // 每个CPU有自己的kernel stack。要解决这个问题，我们就不能使用全局
    // 变量ts，取而代之的,我们使用thiscpu指向的CpuInfo结构体和cpunum函数
    // 来为每个TSS进行初始化,其中thiscpu指向当前运行的cpu的环境,他是结构
    // 体Cpu
	// LAB 4: Your code here:

	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
    // 设置TSS
	//comment ts.ts_esp0 = KSTACKTOP;
	//comment ts.ts_ss0 = GD_KD;
    thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - cpunum() * (KSTKGAP + KSTKSIZE); // esp0是堆栈栈底指针
    thiscpu->cpu_ts.ts_ss0 = GD_KD; // ss0是任务内核态堆栈的段选择符

	// Initialize the TSS slot of the gdt.
	//comment gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts), sizeof(struct Taskstate), 0);
	//comment gdt[GD_TSS0 >> 3].sd_s = 0;
    // 初始化gdt(全局描述表)的TSS(任务状态段)槽,根据文档可知TSS descriptor定义在
    // gdt[(GD_TSS0 >> 3) + i]。
    gdt[(GD_TSS0 >> 3) + cpunum()] = SEG16(STS_T32A, (uint32_t) (&thiscpu->cpu_ts),
        sizeof(struct Taskstate), 0);
    gdt[(GD_TSS0 >> 3) + cpunum()].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	//comment ltr(GD_TSS0);
    // 加载TSS选择子
    //ltr(GD_TSS0 + sizeof(struct Segdesc) * cpunum());
    ltr(GD_TSS0 + (cpunum() << 3));

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

// 调度函数处理相应的中断类型
static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	// 根据中断号调用不同函数处理
	    if (tf->tf_trapno == T_BRKPT) {
		// 根据题目要求断点异常调用monitor函数处理
		monitor(tf);
	    }
        if (tf->tf_trapno == T_PGFLT) {
		// 如果是缺页中断调用page_fault_handler处理
		page_fault_handler(tf);
	    }
	    int r;
	    if (tf->tf_trapno == T_SYSCALL) {
		// 处理系统调用异常syscall(uint32_t syscallno, uint32_t a1, uint32_t a2,
        // uint32_t a3, uint32_t a4, uint32_t a5)，第一个参数为系统调用编号，后面五个参数是系统调用需要的参数，我们可以从inc/syscall.c中知道需要传递的参数分别为AX, DX, CX, BX, DI, SI
		/*r = syscall(tf->tf_regs.reg_eax, tf->tf_regs.reg_edx, tf->tf_regs.reg_ecx, tf->tf_regs.reg_ebx, tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
		if (r < 0) {
		    //panic("trap_dispatch: the system call number is invalid!");
		}
	        根据文档提示将返回值重新赋值给ax
		tf->tf_regs.reg_eax = r;
		return;*/
                tf->tf_regs.reg_eax=syscall(tf->tf_regs.reg_eax,
		tf->tf_regs.reg_edx,tf->tf_regs.reg_ecx,tf->tf_regs.reg_ebx,
		tf->tf_regs.reg_edi,tf->tf_regs.reg_esi);
		return ;
	    }
	


	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.
        if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER) {
		lapic_eoi();
		sched_yield();
		return;
	}

    
	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
        // 根据注释，在做其他工作前需要先加锁
        //>>>>>>for lab4
       lock_kernel();
        //if (tf->tf_cs != GD_KT)lock_kernel();
        //>>>>>>
		assert(curenv);

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}

// 用户处理缺页中断(该函数在trap_dispatch中被调用)
void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();
	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
    // 检查缺页中断发生在用户态还是内核态(检查tf_cs最低2为即可，最低两位为11时表示用户态)
    if ((tf->tf_cs & 3) ==0) {
        // 如果在内核中出现缺页中断就直接终止内核
        panic("page faults occurredrs in kernel-mode");
    }
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.
       if (curenv->env_pgfault_upcall) {
        struct UTrapframe *utf;
        if (UXSTACKTOP - PGSIZE <= tf->tf_esp && tf->tf_esp < UXSTACKTOP) {
            utf = (struct UTrapframe*)(tf->tf_esp - sizeof(struct UTrapframe) - 4);
        } else {
            utf = (struct UTrapframe*)(UXSTACKTOP - sizeof(struct UTrapframe));
        }
        user_mem_assert(curenv, (void*)utf, sizeof(struct UTrapframe), PTE_P|PTE_U | PTE_W);
        utf->utf_fault_va = fault_va;
        utf->utf_err = tf->tf_err;
        utf->utf_regs = tf->tf_regs;
        utf->utf_eip = tf->tf_eip;
        utf->utf_eflags = tf->tf_eflags;
        utf->utf_esp = tf->tf_esp;

       	tf->tf_eip = (uintptr_t)curenv->env_pgfault_upcall;
        tf->tf_esp = (uintptr_t)utf;
        env_run(curenv);
    }
	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

