/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/mmu.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/kclock.h>

// These variables are set by i386_detect_memory()
size_t npages;			// Amount of physical memory (in pages)
static size_t npages_basemem;	// Amount of base memory (in pages)

// These variables are set in mem_init()
pde_t *kern_pgdir;		// Kernel's initial page directory
struct Page *pages;		// Physical page state array
static struct Page *page_free_list;	// Free list of physical pages


// --------------------------------------------------------------
// Detect machine's physical memory setup.
// --------------------------------------------------------------

static int
nvram_read(int r)
{
	return mc146818_read(r) | (mc146818_read(r + 1) << 8);
}

static void
i386_detect_memory(void)
{
	size_t npages_extmem;

	// Use CMOS calls to measure available base & extended memory.
	// (CMOS calls return results in kilobytes.)
	npages_basemem = (nvram_read(NVRAM_BASELO) * 1024) / PGSIZE;
	npages_extmem = (nvram_read(NVRAM_EXTLO) * 1024) / PGSIZE;

	// Calculate the number of physical pages available in both base
	// and extended memory.
	if (npages_extmem)
		npages = (EXTPHYSMEM / PGSIZE) + npages_extmem;
	else
		npages = npages_basemem;

	cprintf("Physical memory: %uK available, base = %uK, extended = %uK\n",
		npages * PGSIZE / 1024,
		npages_basemem * PGSIZE / 1024,
		npages_extmem * PGSIZE / 1024);
}


// --------------------------------------------------------------
// Set up memory mappings above UTOP.
// --------------------------------------------------------------

static void check_page_free_list(bool only_low_memory);
static void check_page_alloc(void);
static void check_kern_pgdir(void);
static physaddr_t check_va2pa(pde_t *pgdir, uintptr_t va);
static void check_page(void);
static void check_page_installed_pgdir(void);
static void boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm);

// This simple physical memory allocator is used only while JOS is setting
// up its virtual memory system.  page_alloc() is the real allocator.
//
// If n>0, allocates enough pages of contiguous physical memory to hold 'n'
// bytes.  Doesn't initialize the memory.  Returns a kernel virtual address.
//
// If n==0, returns the address of the next free page without allocating
// anything.
//
// If we're out of memory, boot_alloc should panic.
// This function may ONLY be used during initialization,
// before the page_free_list list has been set up.
// 分配一块内存空间，然后返回首地址
static void *
boot_alloc(uint32_t n)
{
  static char *nextfree; // virtual address of next byte of free memory
  char *result;
  if (!nextfree) {
    extern char end[];
    nextfree = ROUNDUP((char *) end, PGSIZE);
  }
  // LAB 2: Your code here.
  // 先把nextfree赋值给result，作为要返回的首地址。
  result=nextfree;
  // 然后为nextfree赋新的值，由于要页对齐，所以调用ROUNDUP()向上取整。当n为零时，nextfree的值实际并不会被更新。
  nextfree=ROUNDUP(nextfree+n,PGSIZE);
  // 这句话是判断内是否有足够的空间，如果已经不够了就调用panic()
  if((uint32_t)nextfree-KERNBASE>(npages*PGSIZE))
    panic("Out of memory!\n");
  return result;
}

// Set up a two-level page table:
//    kern_pgdir is its linear (virtual) address of the root
//
// This function only sets up the kernel part of the address space
// (ie. addresses >= UTOP).  The user part of the address space
// will be setup later.
//
// From UTOP to ULIM, the user is allowed to read but not write.
// Above ULIM the user cannot read or write.
// 先检查可用内存大小，然后调用boot_alloc分配一块内存空间给kern_pgdir，然后做各种初始化操作和检查操作
void
mem_init(void)
{
	uint32_t cr0;
	size_t n;

	// Find out how much memory the machine has (npages & npages_basemem).
    // 检查可用内存大小
	i386_detect_memory();

	// Remove this line when you're ready to test this function.
    // 注释了下面一行
    // panic("mem_init: This function is not finished\n");

	//////////////////////////////////////////////////////////////////////
	// create initial page directory.
    // 创建一个page内存给kern_pgdir，并初始化
	kern_pgdir = (pde_t *) boot_alloc(PGSIZE);
	memset(kern_pgdir, 0, PGSIZE);

	//////////////////////////////////////////////////////////////////////
	// Recursively insert PD in itself as a page table, to form
	// a virtual page table at virtual address UVPT.
	// (For now, you don't have understand the greater purpose of the
	// following two lines.)

	// Permissions: kernel R, user R
	kern_pgdir[PDX(UVPT)] = PADDR(kern_pgdir) | PTE_U | PTE_P;

	//////////////////////////////////////////////////////////////////////
	// Allocate an array of npages 'struct Page's and store it in 'pages'.
	// The kernel uses this array to keep track of physical pages: for
	// each physical page, there is a corresponding struct Page in this
	// array.  'npages' is the number of physical pages in memory.
	// Your code goes here:
    // struct Page是用来记录页分配情况的结构，npages是物理页的个数，
// 所以一共需要sizeof(struct Page)*npages bytes 空间来存储这些信息。
// 分配空间并用pages指针指向分配的空间，同时初始化。
pages=(struct Page *)boot_alloc(sizeof(struct Page)*npages);
memset(pages,0,sizeof(struct Page)*npages);

// perm是用来记录权限的。
// n=ROUNDUP(npages*sizeof(struct Page), PGSIZE)计算了页表本身的大小
// page_insert(pde_t *pgdir, struct Page *pp, void *va, int perm)的作用是
// 把虚拟地址 va映射到物理页 pp , 页表 pgdir
// boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm)的作用是
// 把虚拟地址空间[va, va+size) 映射到物理地址[pa, pa+size), 页表 pgdir
int perm = PTE_U | PTE_P;
n = ROUNDUP(npages*sizeof(struct Page), PGSIZE);

// 下面的代码是建立虚拟地址[UPAGES,UPAGES)的部分，映射pages的地址
for(int i=0; i<n; i= i+PGSIZE)
  page_insert(kern_pgdir, pa2page(PADDR(pages) + i), (void *) (UPAGES +i),perm);

// 然后建立`[KSTACKTOP-KSTKSIZE, KSTACKTOP)`部分，映射bootstack的地址
perm = PTE_P|PTE_W;
boot_map_region(kern_pgdir, KSTACKTOP-KSTKSIZE, ROUNDUP(KSTKSIZE,PGSIZE), PADDR(bootstack), perm);

// 最后是`[KERNBASE, 2^32)`部分虚拟地址，映射`[0, 2^32 - KERNBASE)`部分的物理地址
perm=PTE_W|PTE_P;
boot_map_region(kern_pgdir,KERNBASE,ROUNDUP((0xFFFFFFFF-KERNBASE),PGSIZE),0,perm);


	//////////////////////////////////////////////////////////////////////
	// Now that we've allocated the initial kernel data structures, we set
	// up the list of free physical pages. Once we've done so, all further
	// memory management will go through the page_* functions. In
	// particular, we can now map memory using boot_map_region
	// or page_insert
	page_init();

	check_page_free_list(1); // 检查page_free_list中的free pages是否legal;当传入参数1时，因为page_init中构造出的page_free_list中的pages链表是从大编号指向小编号的，但是当前操作系统所采用的页目录表entry_pgdir中没有对大编号页表进行映射，故需要调整page_free_list中的顺序结构
	check_page_alloc();
	check_page();

	//////////////////////////////////////////////////////////////////////
// Now we set up virtual memory

//////////////////////////////////////////////////////////////////////
// Map 'pages' read-only by the user at linear address UPAGES
// Permissions:
//    - the new image at UPAGES -- kernel R, user R
//      (ie. perm = PTE_U | PTE_P)
//    - pages itself -- kernel RW, user NONE
// Your code goes here:

perm = PTE_U | PTE_P;
n = ROUNDUP(npages*sizeof(struct Page), PGSIZE);
for(int i=0; i<n; i= i+PGSIZE)
    page_insert(kern_pgdir, pa2page(PADDR(pages) + i), (void *) (UPAGES +i), perm);

//////////////////////////////////////////////////////////////////////
// Use the physical memory that 'bootstack' refers to as the kernel
// stack.  The kernel stack grows down from virtual address KSTACKTOP.
// We consider the entire range from [KSTACKTOP-PTSIZE, KSTACKTOP)
// to be the kernel stack, but break this into two pieces:
//     * [KSTACKTOP-KSTKSIZE, KSTACKTOP) -- backed by physical memory
//     * [KSTACKTOP-PTSIZE, KSTACKTOP-KSTKSIZE) -- not backed; so if
//       the kernel overflows its stack, it will fault rather than
//       overwrite memory.  Known as a "guard page".
//     Permissions: kernel RW, user NONE
// Your code goes here:
//boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm)

perm = PTE_P|PTE_W;
boot_map_region(kern_pgdir,KSTACKTOP-KSTKSIZE,ROUNDUP(KSTKSIZE,PGSIZE),PADDR(bootstack),perm);

//////////////////////////////////////////////////////////////////////
// Map all of physical memory at KERNBASE.
// Ie.  the VA range [KERNBASE, 2^32) should map to
//      the PA range [0, 2^32 - KERNBASE)
// We might not have 2^32 - KERNBASE bytes of physical memory, but
// we just set up the mapping anyway.
// Permissions: kernel RW, user NONE
// Your code goes here:

perm=PTE_W|PTE_P;
boot_map_region(kern_pgdir,KERNBASE,ROUNDUP((0xFFFFFFFF-KERNBASE),PGSIZE),0,perm);

	// Check that the initial page directory has been set up correctly.
	check_kern_pgdir();

	// Switch from the minimal entry page directory to the full kern_pgdir
	// page table we just created.	Our instruction pointer should be
	// somewhere between KERNBASE and KERNBASE+4MB right now, which is
	// mapped the same way by both page tables.
	//
	// If the machine reboots at this point, you've probably set up your
	// kern_pgdir wrong.
	lcr3(PADDR(kern_pgdir));

	check_page_free_list(0);

	// entry.S set the really important flags in cr0 (including enabling
	// paging).  Here we configure the rest of the flags that we care about.
	cr0 = rcr0();
	cr0 |= CR0_PE|CR0_PG|CR0_AM|CR0_WP|CR0_NE|CR0_MP;
	cr0 &= ~(CR0_TS|CR0_EM);
	lcr0(cr0);

	// Some more checks, only possible after kern_pgdir is installed.
	check_page_installed_pgdir();
}

// --------------------------------------------------------------
// Tracking of physical pages.
// The 'pages' array has one 'struct Page' entry per physical page.
// Pages are reference counted, and free pages are kept on a linked list.
// --------------------------------------------------------------

//
// Initialize page structure and memory free list.
// After this is done, NEVER use boot_alloc again.  ONLY use the page
// allocator functions below to allocate and deallocate physical
// memory via the page_free_list.
// 找到空闲的page，加入到page_free_list链表中
void
page_init(void)
{
  // 首先，计算在extmem区域已经被占用的页的个数
  int num_alloc=((uint32_t)boot_alloc(0)-KERNBASE)/PGSIZE;
  int num_iohole_begin=IOPHYSMEM/PGSIZE;
  int num_iohole_end=EXTPHYSMEM/PGSIZE;
  size_t i;
  for (i = 0; i < npages; i++) {
    if(i==0)//page 0 is not free
    {
      // 实模式中IDT和BIOS结构那部分的物理页不可用，需要保护起来。所以：
      pages[i].pp_ref=1;
    }
    else if(i>=npages_basemem&&i<num_iohole_end+num_alloc)
    {
      //i is in the IO hole or in the page table.
      // [IOPHYSMEM, EXTPHYSMEM) 是IO hole，是不可用的，主要被用来分配给外部设备。
      // 同时，num_alloc已经计算出在extmem区使用的页的个数，也就是[EXTPHYSMEM,EXTPHYSMEM+num_alloc)也已经被分配。
      // 另外，npages_basemem记录的是basemem的页数，也就是IO hole 部分开始的页数
      // 即npages_basemem == num_iohole_begin
      // 所以，[npages_basemem,num_iohole_end+num_alloc)都是不能分配的。
      pages[i].pp_ref=1;
    }
    else
    {
      // 其余的部分都可以使用
      pages[i].pp_ref = 0;
      pages[i].pp_link = page_free_list;
      page_free_list = &pages[i];
    }
  }
}

//
// Allocates a physical page.  If (alloc_flags & ALLOC_ZERO), fills the entire
// returned physical page with '\0' bytes.  Does NOT increment the reference
// count of the page - the caller must do these if necessary (either explicitly
// or via page_insert).
//
// Returns NULL if out of free memory.
//
// Hint: use page2kva and memset
// 分配一个page出去，然后从链表中出去这个page
struct Page *
page_alloc(int alloc_flags)
{
  if(page_free_list==NULL)
    return NULL;
  // 这一部分代码的作用是分配一个物理页，即从 page_free_list 分配出去一个 page 。
  // 方式是返回现在的 page_free_list 指向的 page 地址，然后 page_free_list 指向下一个。
  struct Page * result=page_free_list;
  page_free_list=page_free_list->pp_link;
  result->pp_link=0;

  // 如果需要初始化(alloc_flags&ALLOC_ZERO)就用memset初始化
  if(alloc_flags&ALLOC_ZERO)
    memset(page2kva(result),0,PGSIZE);

  // 最后返回原先的page_free_list值，代表这个被分配出去
  return result;
}

//
// Return a page to the free list.
// (This function should only be called when pp->pp_ref reaches 0.)
// 释放一个page，这个page变成了free状态，然后将这个page加入到page_free_list链表中
void
page_free(struct Page *pp)
{
  // 将一个页放回到free_page_list当中。
  // 先判断，如果pp_ref!=0，代表这个页还在被使用，不能释放。
  // 如果pp->pp_link!=0，代表这个页后面还有其他页，也不能释放。
  if(pp->pp_ref!=0||pp->pp_link!=NULL)
    panic("this page is not free yet");

  // 如果可以释放，就在page_free_list头部插入这个page
  pp->pp_link=page_free_list;
  page_free_list=pp;
  return;
}

//
// Decrement the reference count on a page,
// freeing it if there are no more refs.
//
void
page_decref(struct Page* pp)
{
	if (--pp->pp_ref == 0)
		page_free(pp);
}

// Given 'pgdir', a pointer to a page directory, pgdir_walk returns
// a pointer to the page table entry (PTE) for linear address 'va'.
// This requires walking the two-level page table structure.
//
// The relevant page table page might not exist yet.
// If this is true, and create == false, then pgdir_walk returns NULL.
// Otherwise, pgdir_walk allocates a new page table page with page_alloc.
//    - If the allocation fails, pgdir_walk returns NULL.
//    - Otherwise, the new page's reference count is incremented,
//	the page is cleared,
//	and pgdir_walk returns a pointer into the new page table page.
// 如果create为false，返回NULL;如果分配失败返回NULL,成功的话新创建的page引用加1。返回指向新新页表页的指针.
// Hint 1: you can turn a Page * into the physical address of the
// page it refers to with page2pa() from kern/pmap.h.
//
// Hint 2: the x86 MMU checks permission bits in both the page directory
// and the page table, so it's safe to leave permissions in the page
// more permissive than strictly necessary.
//
// Hint 3: look at inc/mmu.h for useful macros that mainipulate page
// table and page directory entries.
// create=1: 检查va对应的page是否存在，不存在就给他分配一块； create=0: 同上，不存在不分配。 最后返回page table入口地址或NULL 
// 这个函数给了页目录pgdir,以及va为虚拟地址，返回的是页表项pte。
pte_t *
pgdir_walk(pde_t *pgdir, const void *va, int create)
{
    //va as a linear address
    //contains 10 bit DIR and 10 bit PAGE and 12 bit offset.
    // Fill this function in
    int DIR=(unsigned int)va>>22; //get dir
    pde_t * mypgdir=pgdir;
    // create为0时不创建返回NULL，1时创建页表项。
    if(pgdir[DIR]==0&&create==0)
        return NULL;
    if(pgdir[DIR]==0)
    {
        struct Page *page=page_alloc(1);
        if(page==NULL)//no free memory
            return NULL;
        page->pp_ref++;
        pte_t pgAddress=page2pa(page);
        pgAddress |= PTE_U;  //user
        pgAddress |= PTE_P;  //present
        pgAddress |= PTE_W;  //set the privilege level writable
        pgdir[DIR] = pgAddress;
    }
    pte_t pgAdd=pgdir[DIR];
    pgAdd = pgAdd>>12<<12;
    int PAGE =(pte_t)va >>12 & 0x3FF;
    pte_t * pte =(pte_t*) pgAdd + PAGE;
    return KADDR( (pte_t) pte );
}

//
// Map [va, va+size) of virtual address space to physical [pa, pa+size)
// in the page table rooted at pgdir.  Size is a multiple of PGSIZE.
// Use permission bits perm|PTE_P for the entries.
//
// This function is only intended to set up the ``static'' mappings
// above UTOP. As such, it should *not* change the pp_ref field on the
// mapped pages.
//
// Hint: the TA solution uses pgdir_walk
// 该函数将虚拟地址[va, va+size)与物理地址[pa, pa+size)进行映射，并将映射关系加入到pgdir中。该函数只对UTOP之上的部分进行静态映射，pp_ref不会发生变化。分配size个字节就ok了。
// 这个函数将虚拟内存空间[va,size+va)映射到物理空间[pa,pa+size)这个映射关系加到页目录中。
static void
boot_map_region(pde_t *pgdir, uintptr_t va, size_t size, physaddr_t pa, int perm)
{
    // Fill this function in
    // while循环每循环一次，将一个虚拟页和一个物理页的映射关系放到对应的页表项中，一直到size个内存分配完。
    while(size>0)
    {
    pte_t * pte=pgdir_walk(pgdir,(void *)va,1);
    if(pte==NULL)
        return;
    *pte=pa | perm | PTE_P;
    size-=PGSIZE;
    pa+=PGSIZE;
    va+=PGSIZE;
    }
}

//
// Map the physical page 'pp' at virtual address 'va'.
// The permissions (the low 12 bits) of the page table entry
// should be set to 'perm|PTE_P'.
//
// Requirements
//   - If there is already a page mapped at 'va', it should be page_removed().
//   - If necessary, on demand, a page table should be allocated and inserted
//     into 'pgdir'.
//   - pp->pp_ref should be incremented if the insertion succeeds.
//   - The TLB must be invalidated if a page was formerly present at 'va'.
//
// Corner-case hint: Make sure to consider what happens when the same
// pp is re-inserted at the same virtual address in the same pgdir.
// Don't be tempted to write special-case code to handle this
// situation, though; there's an elegant way to address it.
//
// RETURNS:
//   0 on success
//   -E_NO_MEM, if page table couldn't be allocated
//
// Hint: The TA solution is implemented using pgdir_walk, page_remove,
// and page2pa.
// 对pp和va进行映射，如果已经存在remove掉。必要的话分配一个page table并将它插入到pgdir中。插入成功后pp_ref加1。
// 该函数通过给定页目录pgdir，将虚拟地址va映射到物理页框pp上。
int
page_insert(pde_t *pgdir, struct Page *pp, void *va, int perm)
{
    // Fill this function in
    // 只要用pgdir_walk求出va对应的页表项
    pte_t * pte=pgdir_walk(pgdir,va,1);
    // 若未能成功分配页表，返回-E_NO_MEN
    if(pte==NULL)   //if there is no free memory,you cannot create pde
        return -E_NO_MEM;
    //page_remove(pgdir,va);
    if( (pte[0] &  0xFFFFF000) == page2pa(pp))    //whether pp points to pte
        pp->pp_ref--;   //at first ref count decrement for the next increment
    // 若已有物理页对应，调用remove删除；
    else if(*pte != 0)
        page_remove(pgdir, va);
    // 若未有对应，则建立映射关系；
    *pte = (page2pa(pp) & 0xFFFFF000) | perm | PTE_P;
    pp->pp_ref++;
    return 0;
}

//
// Return the page mapped at virtual address 'va'.
// If pte_store is not zero, then we store in it the address
// of the pte for this page.  This is used by page_remove and
// can be used to verify page permissions for syscall arguments,
// but should not be used by most callers.
//
// Return NULL if there is no page mapped at va.
//
// Hint: the TA solution uses pgdir_walk and pa2page.
// 该函数返回页表入口地址
struct Page *
page_lookup(pde_t *pgdir, void *va, pte_t **pte_store)
{
    // Fill this function in
    // 利用pgdir_walk得到pte
    pte_t * pte=pgdir_walk(pgdir,va,0);//find pte
    // 若va==NULL,则返回NULL
    if(pte==NULL)
        return NULL;
    pte_t pa =  *pte>>12<<12;+((unsigned int)va)&0x00000FFF;  //get physcial address
    // 若store！=0，则把pgdir_walk得到的pte存入store，反之，返回NULL
    if(pte_store != 0)
        *pte_store = pte ;
    return pa2page(pa);
}

//
// Unmaps the physical page at virtual address 'va'.
// If there is no physical page at that address, silently does nothing.
//
// Details:
//   - The ref count on the physical page should decrement.
//   - The physical page should be freed if the refcount reaches 0.
//   - The pg table entry corresponding to 'va' should be set to 0.
//     (if such a PTE exists)
//   - The TLB must be invalidated if you remove an entry from
//     the page table.
//
// Hint: The TA solution is implemented using page_lookup,
// 	tlb_invalidate, and page_decref.
// 解除va和其对应的page的映射关系
// 用于删除va的物理页映射
void
page_remove(pde_t *pgdir, void *va)
{
    // Fill this function in
    pte_t *pte=pgdir_walk(pgdir,va,0);
    // 用pgdir_lookup()找到va对应物理页
    struct Page * page=page_lookup(pgdir,va,&pte);
    // 然后删除(相应操作为调用decref()，pte置0，tlb失效)
    if(!page)
          return ;
    page_decref(page);
    *pte=0;
    tlb_invalidate(pgdir, va);
}

//
// Invalidate a TLB entry, but only if the page tables being
// edited are the ones currently in use by the processor.
//
void
tlb_invalidate(pde_t *pgdir, void *va)
{
	// Flush the entry only if we're modifying the current address space.
	// For now, there is only one address space, so always invalidate.
	invlpg(va);
}


// --------------------------------------------------------------
// Checking functions.
// --------------------------------------------------------------

//
// Check that the pages on the page_free_list are reasonable.
//
static void
check_page_free_list(bool only_low_memory)
{
	struct Page *pp;
	int pdx_limit = only_low_memory ? 1 : NPDENTRIES;
	int nfree_basemem = 0, nfree_extmem = 0;
	char *first_free_page;

	if (!page_free_list)
		panic("'page_free_list' is a null pointer!");

	if (only_low_memory) {
		// Move pages with lower addresses first in the free
		// list, since entry_pgdir does not map all pages.
		struct Page *pp1, *pp2;
		struct Page **tp[2] = { &pp1, &pp2 };
		for (pp = page_free_list; pp; pp = pp->pp_link) {
			int pagetype = PDX(page2pa(pp)) >= pdx_limit;
			*tp[pagetype] = pp;
			tp[pagetype] = &pp->pp_link;
		}
		*tp[1] = 0;
		*tp[0] = pp2;
		page_free_list = pp1;
	}

	// if there's a page that shouldn't be on the free list,
	// try to make sure it eventually causes trouble.
	for (pp = page_free_list; pp; pp = pp->pp_link)
		if (PDX(page2pa(pp)) < pdx_limit)
			memset(page2kva(pp), 0x97, 128);

	first_free_page = (char *) boot_alloc(0);
	for (pp = page_free_list; pp; pp = pp->pp_link) {
		// check that we didn't corrupt the free list itself
		assert(pp >= pages);
		assert(pp < pages + npages);
		assert(((char *) pp - (char *) pages) % sizeof(*pp) == 0);

		// check a few pages that shouldn't be on the free list
		assert(page2pa(pp) != 0);
		assert(page2pa(pp) != IOPHYSMEM);
		assert(page2pa(pp) != EXTPHYSMEM - PGSIZE);
		assert(page2pa(pp) != EXTPHYSMEM);
		assert(page2pa(pp) < EXTPHYSMEM || (char *) page2kva(pp) >= first_free_page);

		if (page2pa(pp) < EXTPHYSMEM)
			++nfree_basemem;
		else
			++nfree_extmem;
	}

	assert(nfree_basemem > 0);
	assert(nfree_extmem > 0);
}

//
// Check the physical page allocator (page_alloc(), page_free(),
// and page_init()).
//
static void
check_page_alloc(void)
{
	struct Page *pp, *pp0, *pp1, *pp2;
	int nfree;
	struct Page *fl;
	char *c;
	int i;

	if (!pages)
		panic("'pages' is a null pointer!");

	// check number of free pages
	for (pp = page_free_list, nfree = 0; pp; pp = pp->pp_link)
		++nfree;

	// should be able to allocate three pages
	pp0 = pp1 = pp2 = 0;
	assert((pp0 = page_alloc(0)));
	assert((pp1 = page_alloc(0)));
	assert((pp2 = page_alloc(0)));

	assert(pp0);
	assert(pp1 && pp1 != pp0);
	assert(pp2 && pp2 != pp1 && pp2 != pp0);
	assert(page2pa(pp0) < npages*PGSIZE);
	assert(page2pa(pp1) < npages*PGSIZE);
	assert(page2pa(pp2) < npages*PGSIZE);

	// temporarily steal the rest of the free pages
	fl = page_free_list;
	page_free_list = 0;

	// should be no free memory
	assert(!page_alloc(0));

	// free and re-allocate?
	page_free(pp0);
	page_free(pp1);
	page_free(pp2);
	pp0 = pp1 = pp2 = 0;
	assert((pp0 = page_alloc(0)));
	assert((pp1 = page_alloc(0)));
	assert((pp2 = page_alloc(0)));
	assert(pp0);
	assert(pp1 && pp1 != pp0);
	assert(pp2 && pp2 != pp1 && pp2 != pp0);
	assert(!page_alloc(0));

	// test flags
	memset(page2kva(pp0), 1, PGSIZE);
	page_free(pp0);
	assert((pp = page_alloc(ALLOC_ZERO)));
	assert(pp && pp0 == pp);
	c = page2kva(pp);
	for (i = 0; i < PGSIZE; i++)
		assert(c[i] == 0);

	// give free list back
	page_free_list = fl;

	// free the pages we took
	page_free(pp0);
	page_free(pp1);
	page_free(pp2);

	// number of free pages should be the same
	for (pp = page_free_list; pp; pp = pp->pp_link)
		--nfree;
	assert(nfree == 0);

	cprintf("check_page_alloc() succeeded!\n");
}

//
// Checks that the kernel part of virtual address space
// has been setup roughly correctly (by mem_init()).
//
// This function doesn't test every corner case,
// but it is a pretty good sanity check.
//

static void
check_kern_pgdir(void)
{
	uint32_t i, n;
	pde_t *pgdir;

	pgdir = kern_pgdir;

	// check pages array
	n = ROUNDUP(npages*sizeof(struct Page), PGSIZE);
	for (i = 0; i < n; i += PGSIZE)
		assert(check_va2pa(pgdir, UPAGES + i) == PADDR(pages) + i);


	// check phys mem
	for (i = 0; i < npages * PGSIZE; i += PGSIZE)
		assert(check_va2pa(pgdir, KERNBASE + i) == i);

	// check kernel stack
	for (i = 0; i < KSTKSIZE; i += PGSIZE)
		assert(check_va2pa(pgdir, KSTACKTOP - KSTKSIZE + i) == PADDR(bootstack) + i);
	assert(check_va2pa(pgdir, KSTACKTOP - PTSIZE) == ~0);

	// check PDE permissions
	for (i = 0; i < NPDENTRIES; i++) {
		switch (i) {
		case PDX(UVPT):
		case PDX(KSTACKTOP-1):
		case PDX(UPAGES):
			assert(pgdir[i] & PTE_P);
			break;
		default:
			if (i >= PDX(KERNBASE)) {
				assert(pgdir[i] & PTE_P);
				assert(pgdir[i] & PTE_W);
			} else
				assert(pgdir[i] == 0);
			break;
		}
	}
	cprintf("check_kern_pgdir() succeeded!\n");
}

// This function returns the physical address of the page containing 'va',
// defined by the page directory 'pgdir'.  The hardware normally performs
// this functionality for us!  We define our own version to help check
// the check_kern_pgdir() function; it shouldn't be used elsewhere.

static physaddr_t
check_va2pa(pde_t *pgdir, uintptr_t va)
{
	pte_t *p;

	pgdir = &pgdir[PDX(va)];
	if (!(*pgdir & PTE_P))
		return ~0;
	p = (pte_t*) KADDR(PTE_ADDR(*pgdir));
	if (!(p[PTX(va)] & PTE_P))
		return ~0;
	return PTE_ADDR(p[PTX(va)]);
}


// check page_insert, page_remove, &c
static void
check_page(void)
{
	struct Page *pp, *pp0, *pp1, *pp2;
	struct Page *fl;
	pte_t *ptep, *ptep1;
	void *va;
	int i;
	extern pde_t entry_pgdir[];

	// should be able to allocate three pages
	pp0 = pp1 = pp2 = 0;
	assert((pp0 = page_alloc(0)));
	assert((pp1 = page_alloc(0)));
	assert((pp2 = page_alloc(0)));

	assert(pp0);
	assert(pp1 && pp1 != pp0);
	assert(pp2 && pp2 != pp1 && pp2 != pp0);

	// temporarily steal the rest of the free pages
	fl = page_free_list;
	page_free_list = 0;

	// should be no free memory
	assert(!page_alloc(0));

	// there is no page allocated at address 0
	assert(page_lookup(kern_pgdir, (void *) 0x0, &ptep) == NULL);

	// there is no free memory, so we can't allocate a page table
	assert(page_insert(kern_pgdir, pp1, 0x0, PTE_W) < 0);

	// free pp0 and try again: pp0 should be used for page table
	page_free(pp0);
	assert(page_insert(kern_pgdir, pp1, 0x0, PTE_W) == 0);
	assert(PTE_ADDR(kern_pgdir[0]) == page2pa(pp0));
	assert(check_va2pa(kern_pgdir, 0x0) == page2pa(pp1));
	assert(pp1->pp_ref == 1);
	assert(pp0->pp_ref == 1);

	// should be able to map pp2 at PGSIZE because pp0 is already allocated for page table
	assert(page_insert(kern_pgdir, pp2, (void*) PGSIZE, PTE_W) == 0);
	assert(check_va2pa(kern_pgdir, PGSIZE) == page2pa(pp2));
	assert(pp2->pp_ref == 1);

	// should be no free memory
	assert(!page_alloc(0));

	// should be able to map pp2 at PGSIZE because it's already there
	assert(page_insert(kern_pgdir, pp2, (void*) PGSIZE, PTE_W) == 0);
	assert(check_va2pa(kern_pgdir, PGSIZE) == page2pa(pp2));
	assert(pp2->pp_ref == 1);

	// pp2 should NOT be on the free list
	// could happen in ref counts are handled sloppily in page_insert
	assert(!page_alloc(0));

	// check that pgdir_walk returns a pointer to the pte
	ptep = (pte_t *) KADDR(PTE_ADDR(kern_pgdir[PDX(PGSIZE)]));
	assert(pgdir_walk(kern_pgdir, (void*)PGSIZE, 0) == ptep+PTX(PGSIZE));

	// should be able to change permissions too.
	assert(page_insert(kern_pgdir, pp2, (void*) PGSIZE, PTE_W|PTE_U) == 0);
	assert(check_va2pa(kern_pgdir, PGSIZE) == page2pa(pp2));
	assert(pp2->pp_ref == 1);
	assert(*pgdir_walk(kern_pgdir, (void*) PGSIZE, 0) & PTE_U);
	assert(kern_pgdir[0] & PTE_U);

	// should not be able to map at PTSIZE because need free page for page table
	assert(page_insert(kern_pgdir, pp0, (void*) PTSIZE, PTE_W) < 0);

	// insert pp1 at PGSIZE (replacing pp2)
	assert(page_insert(kern_pgdir, pp1, (void*) PGSIZE, PTE_W) == 0);
	assert(!(*pgdir_walk(kern_pgdir, (void*) PGSIZE, 0) & PTE_U));

	// should have pp1 at both 0 and PGSIZE, pp2 nowhere, ...
	assert(check_va2pa(kern_pgdir, 0) == page2pa(pp1));
	assert(check_va2pa(kern_pgdir, PGSIZE) == page2pa(pp1));
	// ... and ref counts should reflect this
	assert(pp1->pp_ref == 2);
	assert(pp2->pp_ref == 0);

	// pp2 should be returned by page_alloc
	assert((pp = page_alloc(0)) && pp == pp2);

	// unmapping pp1 at 0 should keep pp1 at PGSIZE
	page_remove(kern_pgdir, 0x0);
	assert(check_va2pa(kern_pgdir, 0x0) == ~0);
	assert(check_va2pa(kern_pgdir, PGSIZE) == page2pa(pp1));
	assert(pp1->pp_ref == 1);
	assert(pp2->pp_ref == 0);

	// unmapping pp1 at PGSIZE should free it
	page_remove(kern_pgdir, (void*) PGSIZE);
	assert(check_va2pa(kern_pgdir, 0x0) == ~0);
	assert(check_va2pa(kern_pgdir, PGSIZE) == ~0);
	assert(pp1->pp_ref == 0);
	assert(pp2->pp_ref == 0);

	// so it should be returned by page_alloc
	assert((pp = page_alloc(0)) && pp == pp1);

	// should be no free memory
	assert(!page_alloc(0));

	// forcibly take pp0 back
	assert(PTE_ADDR(kern_pgdir[0]) == page2pa(pp0));
	kern_pgdir[0] = 0;
	assert(pp0->pp_ref == 1);
	pp0->pp_ref = 0;

	// check pointer arithmetic in pgdir_walk
	page_free(pp0);
	va = (void*)(PGSIZE * NPDENTRIES + PGSIZE);
	ptep = pgdir_walk(kern_pgdir, va, 1);
	ptep1 = (pte_t *) KADDR(PTE_ADDR(kern_pgdir[PDX(va)]));
	assert(ptep == ptep1 + PTX(va));
	kern_pgdir[PDX(va)] = 0;
	pp0->pp_ref = 0;

	// check that new page tables get cleared
	memset(page2kva(pp0), 0xFF, PGSIZE);
	page_free(pp0);
	pgdir_walk(kern_pgdir, 0x0, 1);
	ptep = (pte_t *) page2kva(pp0);
	for(i=0; i<NPTENTRIES; i++)
		assert((ptep[i] & PTE_P) == 0);
	kern_pgdir[0] = 0;
	pp0->pp_ref = 0;

	// give free list back
	page_free_list = fl;

	// free the pages we took
	page_free(pp0);
	page_free(pp1);
	page_free(pp2);

	cprintf("check_page() succeeded!\n");
}

// check page_insert, page_remove, &c, with an installed kern_pgdir
static void
check_page_installed_pgdir(void)
{
	struct Page *pp, *pp0, *pp1, *pp2;
	struct Page *fl;
	pte_t *ptep, *ptep1;
	uintptr_t va;
	int i;

	// check that we can read and write installed pages
	pp1 = pp2 = 0;
	assert((pp0 = page_alloc(0)));
	assert((pp1 = page_alloc(0)));
	assert((pp2 = page_alloc(0)));
	page_free(pp0);
	memset(page2kva(pp1), 1, PGSIZE);
	memset(page2kva(pp2), 2, PGSIZE);
	page_insert(kern_pgdir, pp1, (void*) PGSIZE, PTE_W);
	assert(pp1->pp_ref == 1);
	assert(*(uint32_t *)PGSIZE == 0x01010101U);
	page_insert(kern_pgdir, pp2, (void*) PGSIZE, PTE_W);
	assert(*(uint32_t *)PGSIZE == 0x02020202U);
	assert(pp2->pp_ref == 1);
	assert(pp1->pp_ref == 0);
	*(uint32_t *)PGSIZE = 0x03030303U;
	assert(*(uint32_t *)page2kva(pp2) == 0x03030303U);
	page_remove(kern_pgdir, (void*) PGSIZE);
	assert(pp2->pp_ref == 0);

	// forcibly take pp0 back
	assert(PTE_ADDR(kern_pgdir[0]) == page2pa(pp0));
	kern_pgdir[0] = 0;
	assert(pp0->pp_ref == 1);
	pp0->pp_ref = 0;

	// free the pages we took
	page_free(pp0);

	cprintf("check_page_installed_pgdir() succeeded!\n");
}
