// Called from entry.S to get us going.
// entry.S already took care of defining envs, pages, vpd, and vpt.

#include <inc/lib.h>

extern void umain(int argc, char **argv);

const volatile struct Env *thisenv;
const char *binaryname = "<unknown>";

// 该函数负责初始化全局的指向这个程序在 envs[]数组中的Env 结构的 env 指针
void
libmain(int argc, char **argv)
{
	// set thisenv to point at our Env structure in envs[].
	// LAB 3: Your code here.
	// thisenv = 0;
    // 设置thisenv为当前用户进程的Env，通过sys_getenvid可以获取当前运行进程的env_id，然后通过宏ENVX可以将它转换成envs数组中的index
    thisenv = envs + ENVX(sys_getenvid());
	// save the name of the program so that panic() can use it
	if (argc > 0)
		binaryname = argv[0];

	// call user main routine
	umain(argc, argv);

	// exit gracefully
	exit();
}

