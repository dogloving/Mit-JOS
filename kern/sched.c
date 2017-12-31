#include <inc/assert.h>

#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>


// Choose a user environment to run and run it.
// 负责选择一个新环境来运行。
void
sched_yield(void)
{
	struct Env *idle;
	int i;

	// Implement simple round-robin scheduling.
	//
	// Search through 'envs' for an ENV_RUNNABLE environment in
	// circular fashion starting just after the env this CPU was
	// last running.  Switch to the first such environment found.
	//
	// If no envs are runnable, but the environment previously
	// running on this CPU is still ENV_RUNNING, it's okay to
	// choose that environment.
	//
	// Never choose an environment that's currently running on
	// another CPU (env_status == ENV_RUNNING) and never choose an
	// idle environment (env_type == ENV_TYPE_IDLE).  If there are
	// no runnable environments, simply drop through to the code
	// below to switch to this CPU's idle environment.
    // 根据文档和注释，该函数以循环的方式顺序搜索envs数组，从上一个
    // 已经running的环境之后开始。如果找到了就切换到该环境。
    // 1. 如果没有环境是runnable的，但是在该CPU上运行的前一个环境现在
    // 正是ENV_RUNNING状态，就继续选择该环境;
    // 2. 绝不选择一个当前正运行在另一个CPU上的环境(即状态为ENV_RUNNING)，
    // 且绝不选择一个精灵环境(即类型为ENV_TYPE_IDLE)。如果当前没有状态
    // 为可运行的环境，就选择精灵环境
	// LAB 4: Your code here.
    idle = curenv;
    // ENVX获取对应环境的数组下标，即从上一个环境的下一个开始找
    i = idle != NULL ? (ENVX(idle->env_id) + 1) % NENV : 0;
    size_t j;
    for (j = 0; j != NENV; ++j) {
        if (envs[i].env_status == ENV_RUNNABLE) {
            // 如果找到状态为ENV_RUNNABLE的环境，就运行该环境
            env_run(&envs[i]);
            return;
        }
        i = (i + 1) % NENV; // 下一个下标
    }
    // 找了一圈又回来了，如果当前环境仍然是RUNNING的就运行他
    if (idle && idle->env_status == ENV_RUNNING) {
        env_run(idle);
        return;
    }

	// For debugging and testing purposes, if there are no
	// runnable environments other than the idle environments,
	// drop into the kernel monitor.
	for (i = 0; i < NENV; i++) {
		if (envs[i].env_type != ENV_TYPE_IDLE &&
		    (envs[i].env_status == ENV_RUNNABLE ||
		     envs[i].env_status == ENV_RUNNING))
			break;
	}
	if (i == NENV) {
		cprintf("No more runnable environments!\n");
		while (1)
			monitor(NULL);
	}

	// Run this CPU's idle environment when nothing else is runnable.
	idle = &envs[cpunum()];
	if (!(idle->env_status == ENV_RUNNABLE || idle->env_status == ENV_RUNNING))
		panic("CPU %d: No idle environment!", cpunum());
	env_run(idle);
}
