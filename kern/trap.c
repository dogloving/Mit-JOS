#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>

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

	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KSTACKTOP;
	ts.ts_ss0 = GD_KD;

	// Initialize the TSS slot of the gdt.
	gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
					sizeof(struct Taskstate), 0);
	gdt[GD_TSS0 >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0);

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p\n", tf);
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
        // 处理系统调用异常syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)，第一个参数为系统调用编号，后面五个参数是系统调用需要的参数，我们可以从inc/syscall.c中知道需要传递的参数分别为AX, DX, CX, BX, DI, SI
        r = syscall(tf->tf_regs.reg_eax, tf->tf_regs.reg_edx, tf->tf_regs.reg_ecx, tf->tf_regs.reg_ebx, tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
        if (r < 0) {
            panic("trap_dispatch: the system call number is invalid!");
        }
        // 根据文档提示将返回值重新赋值给ax
        tf->tf_regs.reg_eax = r;
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

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	cprintf("Incoming TRAP frame at %p\n", tf);

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		assert(curenv);
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// Return to the current environment, which should be running.
	assert(curenv && curenv->env_status == ENV_RUNNING);
	env_run(curenv);
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
    if ((tf->tf_cs & 3) != 3) {
        // 如果在内核中出现缺页中断就直接终止内核
        panic("page faults occurredrs in kernel-mode");
    }
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}
