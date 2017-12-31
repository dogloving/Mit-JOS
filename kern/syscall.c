/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/syscall.h>
#include <kern/console.h>
#include <kern/sched.h>

// Print a string to the system console.
// The string is exactly 'len' characters long.
// Destroys the environment on memory errors.
static void
sys_cputs(const char *s, size_t len)
{
	// Check that the user has permission to read memory [s, s+len).
	// Destroy the environment if not.

	// LAB 3: Your code here.
    // 通过调用kenr/pmap.c中的函数检查当前运行环境是否有权限访问[s, s + len)内存，如果不能通过env会被销毁，如果env同时是当前环境，将不会返回
    // user_mem_assert(struct Env *env, const void *va, size_t len, int perm)
    user_mem_assert(curenv, (const void*)s, len, PTE_U);
	// Print the string supplied by the user.
	cprintf("%.*s", len, s);
}

// Read a character from the system console without blocking.
// Returns the character, or 0 if there is no input waiting.
static int
sys_cgetc(void)
{
	return cons_getc();
}

// Returns the current environment's envid.
static envid_t
sys_getenvid(void)
{
	return curenv->env_id;
}

// Destroy a given environment (possibly the currently running environment).
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_destroy(envid_t envid)
{
	int r;
	struct Env *e;

	if ((r = envid2env(envid, &e, 1)) < 0)
		return r;
	if (e == curenv)
		cprintf("[%08x] exiting gracefully\n", curenv->env_id);
	else
		cprintf("[%08x] destroying %08x\n", curenv->env_id, e->env_id);
	env_destroy(e);
	return 0;
}

// Deschedule current environment and pick a different one to run.
static void
sys_yield(void)
{
	sched_yield();
}

// Allocate a new environment.
// Returns envid of new environment, or < 0 on error.  Errors are:
//	-E_NO_FREE_ENV if no free environment is available.
//	-E_NO_MEM on memory exhaustion.
//	该系统调用创建一个几乎空白的新环境:返回envid，如果出错返回负数
//	错误包括：
//	-E_NO_FREE_ENV: 如果没有空闲环境是可用的
//	-E_NO_MEM: 内存不足
static envid_t
sys_exofork(void)
{
	// Create the new environment with env_alloc(), from kern/env.c.
	// It should be left as env_alloc created it, except that
	// status is set to ENV_NOT_RUNNABLE, and the register set is copied
	// from the current environment -- but tweaked so sys_exofork
	// will appear to return 0.
    // 通过调用env_alloc创建一个新的环境。将其状态设置为ENV_NOT_RUNNABLE，
    // 寄存器值设置成和其父环境一样。
	// LAB 4: Your code here.
    struct Env *e = NULL;
    int r = env_alloc(&e, curenv->env_id);
    if (r < 0) return r;
    e->env_status = ENV_NOT_RUNNABLE; // 状态设置
    e->env_tf = curenv->env_tf; // env_tf存储了各寄存器的值trapframe
    e->env_tf.tf_regs.reg_eax = 0; // 使该子环境返回0
    return e->env_id; // 返回环境id

	// panic("sys_exofork not implemented");
}

// Set envid's env_status to status, which must be ENV_RUNNABLE
// or ENV_NOT_RUNNABLE.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if status is not a valid status for an environment.
//	设置某个环境状态为ENV_RUNNABLE或ENV_NOT_RUNNABLE,该系统调用一般
//	被用来标记一个新环境已经准备好可用了。
static int
sys_env_set_status(envid_t envid, int status)
{
	// Hint: Use the 'envid2env' function from kern/env.c to translate an
	// envid to a struct Env.
	// You should set envid2env's third argument to 1, which will
	// check whether the current environment has permission to set
	// envid's status.
    // 使用envid2env函数将一个envid转成Env类型对象。
    // 将envid2env的第三个参数设置为1,它将检查当前环境是否有设置状态的权限
	// LAB 4: Your code here.
    if (status != ENV_RUNNABLE && status != ENV_NOT_RUNNABLE) {
        // 要设置的状态必须是ENV_RUNNABLE或者ENV_NOT_RUNNABLE
        return -E_INVAL;
    }
    struct Env *e;
    int r;
    if ((r = envid2env(envid, &e, 1)) < 0) {
        return -E_BAD_ENV;        
    }
    e->env_status = status;
    return 0;
	// panic("sys_env_set_status not implemented");
}

// Set the page fault upcall for 'envid' by modifying the corresponding struct
// Env's 'env_pgfault_upcall' field.  When 'envid' causes a page fault, the
// kernel will push a fault record onto the exception stack, then branch to
// 'func'.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
static int
sys_env_set_pgfault_upcall(envid_t envid, void *func)
{
	// LAB 4: Your code here.
	struct Env *e;
	if(envid2env(envid,&e,1)<0){
		return -E_BAD_ENV;
	}
	e->env_pgfault_upcall=func;
	//user_mem_assert(e,func,4,0);
	return 0;
	//panic("sys_env_set_pgfault_upcall not implemented");
}

// Allocate a page of memory and map it at 'va' with permission
// 'perm' in the address space of 'envid'.
// The page's contents are set to 0.
// If a page is already mapped at 'va', that page is unmapped as a
// side effect.
//
// perm -- PTE_U | PTE_P must be set, PTE_AVAIL | PTE_W may or may not be set,
//         but no other bits may be set.  See PTE_SYSCALL in inc/mmu.h.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	-E_INVAL if perm is inappropriate (see above).
//	-E_NO_MEM if there's no memory to allocate the new page,
//		or to allocate any necessary page tables.
//	分配一个page大小的内存，并且将其映射到虚拟地址va，包含envid
//	的地址空间的权限perm。该page的内容设置为0.如果某个page已经被
//	映射到va了，那么一个副作用就是将会取消那个page的映射。
static int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	// Hint: This function is a wrapper around page_alloc() and
	//   page_insert() from kern/pmap.c.
	//   Most of the new code you write should be to check the
	//   parameters for correctness.
	//   If page_insert() fails, remember to free the page you
	//   allocated!
    // 需要检查参数的正确性。如果page-insert失败了，要释放分配的page
	// LAB 4: Your code here.
    if (va >= (void*)UTOP) {
        // 检查虚拟地址
        return -E_INVAL;
    }
    if ((perm & PTE_U) == 0 || (perm & PTE_P) == 0) {
        // 检查权限
        return -E_INVAL; 
    }
    if ((perm & ~PTE_SYSCALL) != 0) {
        return -E_INVAL;
    }
    struct Env *e;
    if (envid2env(envid, &e, 1) < 0) {
        // 检查该环境是否有效
        return -E_BAD_ENV;
    }
    struct Page *p;
    if ((p = page_alloc(ALLOC_ZERO)) == NULL) {
        return -E_NO_MEM;
    }
    if (page_insert(e->env_pgdir, p, va, perm) < 0) {
        // 插入失败要进行释放
        page_free(p);
        return -E_NO_MEM;
    }
    // 根据注释需要将内容设置为0
    memset(page2kva(p), 0, PGSIZE);
    return 0;

	// panic("sys_page_alloc not implemented");
}

// Map the page of memory at 'srcva' in srcenvid's address space
// at 'dstva' in dstenvid's address space with permission 'perm'.
// Perm has the same restrictions as in sys_page_alloc, except
// that it also must not grant write access to a read-only
// page.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if srcenvid and/or dstenvid doesn't currently exist,
//		or the caller doesn't have permission to change one of them.
//	-E_INVAL if srcva >= UTOP or srcva is not page-aligned,
//		or dstva >= UTOP or dstva is not page-aligned.
//	-E_INVAL is srcva is not mapped in srcenvid's address space.
//	-E_INVAL if perm is inappropriate (see sys_page_alloc).
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in srcenvid's
//		address space.
//	-E_NO_MEM if there's no memory to allocate any necessary page tables.
// 复制一个环境的page mapping到另一个环境，使得新老环境指向物理内存的同
// 一页。权限与sys_page_alloc中相同。
static int
sys_page_map(envid_t srcenvid, void *srcva,
	     envid_t dstenvid, void *dstva, int perm)
{
	// Hint: This function is a wrapper around page_lookup() and
	//   page_insert() from kern/pmap.c.
	//   Again, most of the new code you write should be to check the
	//   parameters for correctness.
	//   Use the third argument to page_lookup() to
	//   check the current permissions on the page.
    // 需要检查参数的正确性
	// LAB 4: Your code here.
    if (srcva >= (void*)UTOP || ROUNDUP(srcva, PGSIZE) != srcva
        || dstva >= (void*)UTOP || ROUNDUP(dstva, PGSIZE) != dstva) {
        return -E_INVAL;
    }
    // 检查perm
    if ((perm & PTE_U) == 0 || (perm & PTE_P) == 0) {
        return -E_INVAL;
    }
    if ((perm & ~PTE_SYSCALL) != 0) {
        return -E_INVAL;
    }
    // 检查srcenv和dstenv是否都是有效的
    struct Env *srcenv, *dstenv;
    if (envid2env(srcenvid, &srcenv, 1) < 0) {
        return -E_BAD_ENV;
    }
    if (envid2env(dstenvid, &dstenv, 1) < 0) {
        return -E_BAD_ENV;
    }
    // page_lookup返回页表入口地址 
    struct Page *p;
    pte_t *pte;
    p = page_lookup(srcenv->env_pgdir, srcva, &pte);
    if ((*pte & PTE_W) == 0 && (perm & PTE_W) == 1) {
        return -E_INVAL;
    }
    if (page_insert(dstenv->env_pgdir, p, dstva, perm) < 0) {
        return -E_NO_MEM;
    }
    return 0;

	// panic("sys_page_map not implemented");
}

// Unmap the page of memory at 'va' in the address space of 'envid'.
// If no page is mapped, the function silently succeeds.
//
// Return 0 on success, < 0 on error.  Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist,
//		or the caller doesn't have permission to change envid.
//	-E_INVAL if va >= UTOP, or va is not page-aligned.
//	解除映射关系
static int
sys_page_unmap(envid_t envid, void *va)
{
	// Hint: This function is a wrapper around page_remove().

	// LAB 4: Your code here.
    if (va >= (void*)UTOP || ROUNDUP(va, PGSIZE) != va) {
        return -E_INVAL;
    }
    struct Env *e;
    if (envid2env(envid, &e, 1) < 0) {
        return -E_BAD_ENV;
    }
    // page_remove用于删除va的物理页映射
    page_remove(e->env_pgdir, va);
    return 0;

	// panic("sys_page_unmap not implemented");
}

// Try to send 'value' to the target env 'envid'.
// If srcva < UTOP, then also send page currently mapped at 'srcva',
// so that receiver gets a duplicate mapping of the same page.
//
// The send fails with a return value of -E_IPC_NOT_RECV if the
// target is not blocked, waiting for an IPC.
//
// The send also can fail for the other reasons listed below.
//
// Otherwise, the send succeeds, and the target's ipc fields are
// updated as follows:
//    env_ipc_recving is set to 0 to block future sends;
//    env_ipc_from is set to the sending envid;
//    env_ipc_value is set to the 'value' parameter;
//    env_ipc_perm is set to 'perm' if a page was transferred, 0 otherwise.
// The target environment is marked runnable again, returning 0
// from the paused sys_ipc_recv system call.  (Hint: does the
// sys_ipc_recv function ever actually return?)
//
// If the sender wants to send a page but the receiver isn't asking for one,
// then no page mapping is transferred, but no error occurs.
// The ipc only happens when no errors occur.
//
// Returns 0 on success, < 0 on error.
// Errors are:
//	-E_BAD_ENV if environment envid doesn't currently exist.
//		(No need to check permissions.)
//	-E_IPC_NOT_RECV if envid is not currently blocked in sys_ipc_recv,
//		or another environment managed to send first.
//	-E_INVAL if srcva < UTOP but srcva is not page-aligned.
//	-E_INVAL if srcva < UTOP and perm is inappropriate
//		(see sys_page_alloc).
//	-E_INVAL if srcva < UTOP but srcva is not mapped in the caller's
//		address space.
//	-E_INVAL if (perm & PTE_W), but srcva is read-only in the
//		current environment's address space.
//	-E_NO_MEM if there's not enough memory to map srcva in envid's
//		address space.
static int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, unsigned perm)
{
	// LAB 4: Your code here.
	struct Env *e;
	if (envid2env(envid, &e, 0) < 0) {
	return -E_BAD_ENV;
	}
	if (!(e->env_ipc_recving)) {
	return -E_IPC_NOT_RECV;
	}
	if (e->env_ipc_dstva && srcva && (uintptr_t) srcva < UTOP) {
	int r = sys_page_map(0, srcva, envid, e->env_ipc_dstva, perm);
	if (r < 0) {
	    return r;
	}
	e->env_ipc_perm = perm;
	} else {
	e->env_ipc_perm = 0;
	}
	e->env_ipc_value = value;
	e->env_ipc_from = curenv->env_id;

	e->env_tf.tf_regs.reg_eax = 0;
	e->env_ipc_recving = 0;
	e->env_status = ENV_RUNNABLE;

	return 0;
	//panic("sys_ipc_try_send not implemented");
}

// Block until a value is ready.  Record that you want to receive
// using the env_ipc_recving and env_ipc_dstva fields of struct Env,
// mark yourself not runnable, and then give up the CPU.
//
// If 'dstva' is < UTOP, then you are willing to receive a page of data.
// 'dstva' is the virtual address at which the sent page should be mapped.
//
// This function only returns on error, but the system call will eventually
// return 0 on success.
// Return < 0 on error.  Errors are:
//	-E_INVAL if dstva < UTOP but dstva is not page-aligned.
static int
sys_ipc_recv(void *dstva)
{
	// LAB 4: Your code here.
	if ((uintptr_t) dstva >= UTOP || (dstva && (uintptr_t) dstva % PGSIZE)) {
	return -E_INVAL;
	}
	curenv->env_ipc_recving = 1;
	curenv->env_ipc_dstva = dstva;
	curenv->env_status = ENV_NOT_RUNNABLE;

	sched_yield();
}

// Dispatches to the correct kernel function, passing the arguments.
int32_t
syscall(uint32_t syscallno, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	// Call the function corresponding to the 'syscallno' parameter.
	// Return any appropriate return value.
	// LAB 3: Your code here.
    // 根据lib/syscall.c，可知各syscallno值对应调用的函数
    if (syscallno == SYS_cputs) {
        sys_cputs((const char*)a1, a2);
        return 0;
    } else if (syscallno == SYS_cgetc) {
        return sys_cgetc();
    } else if (syscallno == SYS_getenvid) {
        return sys_getenvid();
    } else if (syscallno == SYS_env_destroy) {
        return sys_env_destroy(a1);
    } else if (syscallno == SYS_yield) {
        // for lab4
        sched_yield();
    }
    //>>>>>>for lab4
    else if (syscallno == SYS_page_alloc)
        return sys_page_alloc(a1, (void*) a2, a3);
    else if(syscallno == SYS_page_map)
        return sys_page_map(a1, (void*) a2, a3, (void*) a4, a5);
    else if(syscallno == SYS_page_unmap)
        return sys_page_unmap(a1, (void*) a2);
    else if(syscallno == SYS_exofork)
        return sys_exofork();
    else if(syscallno == SYS_env_set_status)
        return sys_env_set_status(a1, a2);
    else if(syscallno == SYS_ipc_try_send)
        return sys_ipc_try_send(a1, a2,(void*) a3,a4);    
    else if(syscallno == SYS_ipc_recv)
        return sys_ipc_recv((void*) a1); 
    //>>>>>>
    else if(SYS_env_set_pgfault_upcall){
		return sys_env_set_pgfault_upcall(a1,(void*)a2);
	}
    else {
        return -E_INVAL;
    }
	panic("syscall not implemented");
}

