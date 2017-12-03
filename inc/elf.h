#ifndef JOS_INC_ELF_H
#define JOS_INC_ELF_H

#define ELF_MAGIC 0x464C457FU	/* "\x7FELF" in little endian */
/* ELF: Executable and Linkable Format */
struct Elf {			// ELF header
	uint32_t e_magic;	// must equal ELF_MAGIC
	uint8_t e_elf[12];	// magic number相关信息
	uint16_t e_type;	// 文件类型，1：可重定位的；2：可执行的；3：共享的；4：核心的
	uint16_t e_machine;	// 机器指令集结构，如0x03：x86；0x08：MIPS
	uint32_t e_version;	// ELF文件版本
	uint32_t e_entry;	// 程序内存中入口地址
	uint32_t e_phoff;	// program header table偏移地址
	uint32_t e_shoff;	// section header table偏移地址
	uint32_t e_flags;	// 与机器的架构相关的值
	uint16_t e_ehsize;	// ELF header大小
	uint16_t e_phentsize;	// pragram header table条目大小
	uint16_t e_phnum;	// pragram header table条目数量
	uint16_t e_shentsize;	// section header table条目大小
	uint16_t e_shnum;	// section header table条目数量
	uint16_t e_shstrndx;	// 存着包含section name的section header table入口的索引
};

struct Proghdr {
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_va;
	uint32_t p_pa;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
};

struct Secthdr {
	uint32_t sh_name;
	uint32_t sh_type;
	uint32_t sh_flags;
	uint32_t sh_addr;
	uint32_t sh_offset;
	uint32_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint32_t sh_addralign;
	uint32_t sh_entsize;
};

// Values for Proghdr::p_type
#define ELF_PROG_LOAD		1

// Flag bits for Proghdr::p_flags
#define ELF_PROG_FLAG_EXEC	1
#define ELF_PROG_FLAG_WRITE	2
#define ELF_PROG_FLAG_READ	4

// Values for Secthdr::sh_type
#define ELF_SHT_NULL		0
#define ELF_SHT_PROGBITS	1
#define ELF_SHT_SYMTAB		2
#define ELF_SHT_STRTAB		3

// Values for Secthdr::sh_name
#define ELF_SHN_UNDEF		0

#endif /* !JOS_INC_ELF_H */
