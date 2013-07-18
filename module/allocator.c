#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tty.h>  /* tty_struct */
#include <linux/sched.h>  /* current*/
#include <linux/slab.h> /* alloc_page */
#include <asm-generic/memory_model.h> /* page_to_pfn, atomic_set */
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/color_alloc.h>
#include <linux/mm.h> /* page_zone */
#include <linux/page-flags.h> /* PageCompound, PageHighMem */
#include <linux/string.h> /* memset */
#include <linux/highmem.h>  /* kmap/kunmap */
#include <linux/rwsem.h>
#include "list.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ying Ye <yingy@bu.edu>");

#define ALLOC_DEBUG
#define ROUND_ROBIN
//#define USER_STATIC

extern struct page * (*colored_alloc)(struct mm_struct *mm);
extern struct page * (*colored_alloc_file)(struct file *filp);
extern void (*assign_colors)(struct mm_struct *mm);
extern int (*colored_free)(struct page *pg, struct zone *zone);
extern int (*check_apps)(struct file *filp);

/* 
 * XXX: hard-coded 32-bit system, LLC size 4MB, 16 ways, page size 4KB
 * color number = (LLC size / number of ways) / page size
 */
#define PG_SIZE (4*1024)
/* if color number is changed, GET_COLOR should be modified */
#define COLOR_NUM (64)
/* 1GB RAM for coloring */
#define RAM_SIZE (1024*1024*1024)


/* array of colors */
static LIST color_lists[COLOR_NUM];
/* 
 * used when filling in memory pool
 * page of unwanted color should not be freed before pool is full
 * otherwise, it may be reallocated to us again and again
 */
static LIST page_buf;
/* locks for each color list */
static spinlock_t color_locks[COLOR_NUM];

/* 
 * memory reserve for NODE 
 * XXX: kmalloc should not be used after alloc_init,
 * since it may call our module
 */
struct _Node_Cache {
  LIST list;
  spinlock_t lock;
};

static struct _Node_Cache node_cache;

static int pg_num;

#ifdef ROUND_ROBIN
/* current color */
static int color_index;
static spinlock_t index_lock;
/* current max is 64 */
#define COLOR_QUOTA 32
#endif

static struct page template;
static int e_counter = 0;

#ifdef USER_STATIC
#define MAX_APPS 10
static char *apps[MAX_APPS];
static int nr_apps;
module_param_array(apps, charp, &nr_apps, 0644);

static int quanta[MAX_APPS];
module_param_array(quanta, int, NULL, 0644);

static struct color_set assignment[MAX_APPS];

struct pureHack {
  int hit[MAX_APPS];
  struct address_space *mapping[MAX_APPS];
  struct address_space *target[MAX_APPS];
  int cur_color[MAX_APPS];
};

static struct pureHack hackdata;
#endif


/* *********Utilities********* */
#define GET_COLOR(pfn) (pfn & 0x3F)


static void init_check(void) {

  int i, j;
  for(i = 0; i < COLOR_NUM; i++) {
    if(color_lists[i].num != pg_num) {
      printk(KERN_ERR "color %d not full: %d pages\n", i, color_lists[i].num);
    }

    NODE *cur = color_lists[i].head;
    int flag = 0;
    for(j = 0; j < pg_num; j++) {
      if(GET_COLOR(page_to_pfn((struct page *)(cur->data))) != i) {
        flag = 1;
      }
      cur = cur->next; 
    }

    if(flag) {
      printk(KERN_ERR "color %d has pages of different colors\n", i);
    }
  }
}

static void check_lists(void) {

  int i, flag = 0;
  for(i = 0; i < COLOR_NUM; i++) {
    if(color_lists[i].num != 0) {
      flag = 1;
      printk(KERN_ERR "color not freed: %d\n", i);
    }
  }
  if(flag) printk(KERN_ERR "Memory pool not freed completely!\n");
}

static void check_cache(void) {

  printk(KERN_ERR "cache: %d\n", node_cache.list.num);
}


static void free_list_pgs(LIST *list) {

  NODE *node;
  while(1) {
    node = list_remove(list);
    if(node == NULL) break;
    if(node->data != NULL) {
      __free_page((struct page *)(node->data));
    }
    kfree(node);
  }
}

static NODE *node_alloc(void) {

  NODE *node;

  spin_lock(&node_cache.lock);

  node = list_remove(&node_cache.list);

  spin_unlock(&node_cache.lock);

#ifdef ALLOC_DEBUG
  if(node == NULL) {
    printk(KERN_ERR "%s: bug in list management!\n", __func__);
  }
#endif

  return node;
}

static void node_free(NODE *node) {

  spin_lock(&node_cache.lock);

  list_insert(&node_cache.list, NULL, node);

  spin_unlock(&node_cache.lock);

#ifdef ALLOC_DEBUG
  if(node_cache.list.num > (RAM_SIZE / PG_SIZE)) {
    printk(KERN_ERR "%s: bug in list management!\n", __func__);
  }
#endif
}

static void my_dump_page(struct page *pg) {

  printk(KERN_ERR "%x %x %x %x %x %x %x %x", pg->flags, pg->_count.counter, 
        pg->_mapcount.counter, pg->private, (long)pg->mapping, pg->index, 
        (long)pg->lru.next, (long)pg->lru.prev);
  printk(KERN_ERR "\n");
}

static void check_page(struct page *pg) {

  if(pg->_count.counter != template._count.counter) goto next;
  if(pg->_mapcount.counter != template._mapcount.counter) goto next;
  if(pg->mapping != template.mapping) goto next;
  if(pg->lru.next != template.lru.next) goto next;
  if(pg->lru.prev != template.lru.prev) goto next;

  return;

next:
  e_counter++;
  my_dump_page(pg);
}

static void zero_page(struct page *pg, unsigned long frame, const char *name) {

  void *addr = kmap_atomic(pg);

  memset(addr, 0, PG_SIZE);
  kunmap_atomic(addr);
}

static void check_assignment(void) {

#ifdef USER_STATIC
  int i, j;
  for(i = 0; i < nr_apps; i++) {
    printk(KERN_ERR "%s:", apps[i]);
    for(j = 0; j < quanta[i]; j++) {
      printk(KERN_ERR " %d", assignment[i].colors[j]);
    }
    printk(KERN_ERR "\n");
  }
#endif
}

static int string_eq(char *str1, char *str2) {

  int i = 0;
  while(str1[i] != '\0' && str2[i] != '\0') {
    if(str1[i] != str2[i]) return 0;
    i++;
  }

  return 1;
}


struct page *alloc_colored_page(struct mm_struct *mm);
void get_color_set(struct mm_struct *mm);
int free_colored_page(struct page *pg, struct zone *zone);
int apps_check(struct file *filp);
struct page *alloc_colored_page_file(struct file *filp);

/* *********Allocator********* */

static int __init alloc_init(void) {

  /* -ZC- pg_num: the number of pages each color has */
  pg_num = RAM_SIZE / (COLOR_NUM * PG_SIZE);
  struct page *new_pg;

  /* initialize NODE cache */
  /* -ZC- From this, we can guess that */
  /* NODE is actually page */
  /* Here it gets 1G memory area from */
  /* system memory allocator, serving as pool */
  /* reference it with variable node_cache */
  /* Q: Are these nodes physically continuous? */
  int k;
  NODE *temp;
  for(k = 0; k < (RAM_SIZE / PG_SIZE); k++) {
    temp = kmalloc(sizeof(NODE), GFP_KERNEL);
    if(!temp) {
      printk(KERN_ERR "Fails to get NODE!\n");
      return 1;
    }
    list_insert(&node_cache.list, NULL, temp);
  }
  spin_lock_init(&node_cache.lock);

#ifdef ALLOC_DEBUG
  check_cache();
#endif

  /* initialize locks */
  for(k = 0; k < COLOR_NUM; k++)
    spin_lock_init(&color_locks[k]);

#ifdef USER_STATIC
  int start = 0, abcd;
  for(abcd = 0; abcd < nr_apps; abcd++) {
    k = 0;

    if(quanta[abcd] > COLOR_BASE) {
      printk(KERN_ERR "quanta is larger than max!\n");
      return 1;
    }

    while(k < quanta[abcd]) {
      assignment[abcd].colors[k] = start;
      k++;
      start = (start + 1) % COLOR_NUM;
    }
  }

#ifdef ALLOC_DEBUG
  check_assignment();
#endif
#endif

#ifdef ROUND_ROBIN
  spin_lock_init(&index_lock);
  color_index = 0;
#endif

  /* fill in memory pool */
  int count = 0, color, num;
  unsigned long frame;

#ifdef ALLOC_DEBUG
  struct page *t_pg;
  t_pg = alloc_page(__GFP_HIGHMEM | __GFP_MOVABLE | __GFP_ZERO);

  template._count.counter = t_pg->_count.counter;
  template._mapcount.counter = t_pg->_mapcount.counter;
  template.mapping = t_pg->mapping;
  template.lru.next = t_pg->lru.next;
  template.lru.prev = t_pg->lru.prev;
#endif

  while(count != COLOR_NUM) {
    new_pg = alloc_page(__GFP_HIGHMEM | __GFP_MOVABLE | __GFP_ZERO);

    frame = page_to_pfn(new_pg);
    color = GET_COLOR(frame);

    num = color_lists[color].num;
    if(num >= pg_num) { /* color list is full */
      if(!list_insert(&page_buf, new_pg, (NODE *)kmalloc(sizeof(NODE), GFP_KERNEL))) {
        printk(KERN_ERR "Fails to alloc a node!\n");
        return 1;
      }
    }
    else {
#ifdef ALLOC_DEBUG
      check_page(new_pg);
#endif

      if(!list_insert(&color_lists[color], new_pg, node_alloc())) {
        printk(KERN_ERR "Fails to alloc a node!\n");
        return 1;
      }

      if(color_lists[color].num == pg_num) count++;
    }
  }

#ifdef ALLOC_DEBUG
  __free_page(t_pg);
  printk(KERN_ERR "counter: %d\n", e_counter);
#endif

  /* free page buffer */
  free_list_pgs(&page_buf);

  /* load functions */
  colored_free = free_colored_page;
  colored_alloc = alloc_colored_page;
  colored_alloc_file = alloc_colored_page_file;
  check_apps = apps_check;
  assign_colors = get_color_set;  

#ifdef ALLOC_DEBUG
  init_check();
#endif

  printk(KERN_ERR "Allocator loaded!\n");
  return 0;
}


/* memory allocated to user processes is not freed back to this module but to Buddy system */
static void __exit alloc_cleanup(void) {

  //my_page_table_walk();

  int i;
  for(i = 0; i < COLOR_NUM; i++) {
    spin_lock(&color_locks[i]);
  }

  /* unload functions */
  // XXX: synchronization may be needed
  assign_colors = NULL;
  check_apps = NULL;
  colored_alloc_file = NULL;
  colored_alloc = NULL;
  colored_free = NULL;

  /* free memory pool */
  for(i = 0; i < COLOR_NUM; i++) {
    free_list_pgs(&color_lists[i]);
  }

  for(i = 0; i < COLOR_NUM; i++) {
    spin_unlock(&color_locks[i]);
  }

  free_list_pgs(&page_buf);
  free_list_pgs(&node_cache.list);

#ifdef ALLOC_DEBUG
  check_lists();
#endif

  printk(KERN_ERR "Allocator unloaded!\n");
}

static struct page *internal_alloc_page(int color) {

#ifdef ALLOC_DEBUG
  if(color >= COLOR_NUM || color < 0) {
    printk(KERN_ERR "%s: Invalid color!\n", __func__);
    return NULL;
  }
#endif

  spin_lock(&color_locks[color]);

  /* running out of memory */
  if(color_lists[color].num <= 0) {
    spin_unlock(&color_locks[color]);
    return NULL;
  }

  NODE *node = list_remove(&color_lists[color]);
  struct page *new_pg = (struct page *)(node->data);
  node_free(node);

  spin_unlock(&color_locks[color]);

#ifdef ALLOC_DEBUG 
  if(new_pg == NULL) {
    printk(KERN_ERR "%s: bug for alloc!\n", __func__);
  }
#endif

  return new_pg;
}

/* called by free_hot_cold_page */
int free_colored_page(struct page *pg, struct zone *zone) {

  unsigned long frame;
  int color;

  /* only take HighMem pages */
  if(zone->name[0] != 'H') {
    return 0;
  }

  frame = page_to_pfn(pg);
  color = GET_COLOR(frame);

  spin_lock(&color_locks[color]);

  if(color_lists[color].num >= pg_num) {
    spin_unlock(&color_locks[color]);
    return 0;
  }
  else {
    atomic_set(&(pg->_count), 1);

    //XXX: maybe only zero pages when needed
    zero_page(pg, frame, zone->name);
      
    if(!list_insert(&color_lists[color], pg, node_alloc())) {
      printk(KERN_ERR "Fails to alloc a node!\n");

      spin_unlock(&color_locks[color]);
      return 0;
    }

    spin_unlock(&color_locks[color]);

    //printk(KERN_ERR "freed color: %d\n", color);
/*   
    printk(KERN_ERR "freed: %x %x %x %x %x %x\n", pg->flags, pg->_count.counter, 
        pg->_mapcount.counter, pg->private, (long)pg->mapping, 
        pg->origin);
*/
    return 1;
  }
}


/* called by page fault handler */
struct page *alloc_colored_page(struct mm_struct *mm) {

  struct page *new_pg;
  int counter = 0;
  struct color_set *set_ptr;

  if(mm == NULL) return NULL;

  if(mm->color_num == 0) return NULL;

  set_ptr = &(mm->my_colors);
	
  spin_lock(&mm->cur_lock);

  do {
    new_pg = internal_alloc_page(set_ptr->colors[mm->color_cur]);
    mm->color_cur = (mm->color_cur + 1) % (mm->color_num);
    counter++;
    /* if color is out of memory, try another one */
  } while(new_pg == NULL && counter < mm->color_num);

  spin_unlock(&mm->cur_lock);

#ifdef ALLOC_DEBUG
  if(!new_pg) {
    printk(KERN_ERR "%s: out of memory!\n", __func__);
  }
#endif

  return new_pg; 
}

/* called by __do_page_cache_readahead */
struct page *alloc_colored_page_file(struct file *filp) {

#ifdef USER_STATIC
  int i;
  for(i = 0; i < nr_apps; i++) {
    if(string_eq(filp->f_dentry->d_iname, apps[i])) break;
  }

  struct page *pg;
  int index = hackdata.cur_color[i];
  int count = 0;
  do {
    pg = internal_alloc_page(assignment[i].colors[index]);
    index = (index + 1) % quanta[i];
    count++;
  } while(pg == NULL && count < quanta[i]);

  hackdata.cur_color[i] = index;

  return pg;
#else

  return NULL;
#endif
}

/* called by generic_perform_write, which calls ext4_da_write_begin */
int apps_check(struct file *filp) {

#ifdef USER_STATIC
  int i;
  for(i = 0; i < nr_apps; i++) {
    if(string_eq(filp->f_dentry->d_iname, apps[i])) {
      if(filp->f_mapping == hackdata.target[i] && hackdata.hit[i] == 2) {
        return 1;
      }
      else {
        if(hackdata.hit[i] == 0) {
          hackdata.mapping[i] = filp->f_mapping;
          hackdata.hit[i]++;
          return 0;
        }

        if(hackdata.hit[i] == 1 && hackdata.mapping[i] != filp->f_mapping) {
          hackdata.target[i] = filp->f_mapping;
          hackdata.hit[i]++;
          return 1;
        }

        return 0;
      }
    }
  }
#endif

  return 0;
}

/* called by do_execve */
void get_color_set(struct mm_struct *mm) {

#ifdef ALLOC_DEBUG
  if(mm == NULL) {
    printk(KERN_ERR "Invalid mm argument!\n");
    return;
  }
#endif

#ifdef USER_STATIC
  int i;
  for(i = 0; i < nr_apps; i++) {
    if(string_eq(current->comm, apps[i])) break;
  }

  /* not a target */
  if(i == nr_apps) return;

  int index = 0;
  struct color_set *set_ptr = &(mm->my_colors);

  while(index < quanta[i]) {
    set_ptr->colors[index] = assignment[i].colors[index];
    index++;
  }

  mm->color_num = quanta[i];
  mm->color_cur = 0;

#endif
 
#ifdef ROUND_ROBIN
  int index = 0;
  struct color_set *set_ptr = &(mm->my_colors);

  spin_lock(&index_lock);

  while(index < COLOR_QUOTA) {
    set_ptr->colors[index] = color_index;
    printk(KERN_ERR "color %d ", color_index);
    index++;
    color_index = (color_index + 1) % COLOR_NUM;
  }

  spin_unlock(&index_lock);

  mm->color_num = COLOR_QUOTA;
  mm->color_cur = 0;

#endif

#ifdef ALLOC_DEBUG
  printk(KERN_ERR "%s (pid %d tgid %d colors %d): code %x - %x!\n", current->comm,
    current->pid, current->tgid, mm->color_num, mm->start_code, mm->end_code);
#endif
}


module_init(alloc_init);
module_exit(alloc_cleanup);

/* vi: set et sw=2 sts=2: */
