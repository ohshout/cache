#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tty.h>  /* tty_struct */
#include <linux/sched.h>  /* current, find_task_by_vpid, for_each_process */
#include <linux/slab.h> /* alloc_page */
#include <asm-generic/memory_model.h> /* page_to_pfn */
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/proc_fs.h>  /* proc_dir_entry */
#include <linux/color_alloc.h>
#include "list.h"
#include "heap.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ying Ye <yingy@bu.edu>");

#define ALLOC_DEBUG
#define ROUND_ROBIN

#ifdef NEW_ALLOC
extern struct page * (*colored_alloc)(struct mm_struct *mm);
extern void (*assign_colors)(struct mm_struct *mm);
#endif

/* 
 * XXX: hard-coded 32-bit system, LLC size 4MB, 16 ways, page size 4KB
 * color number = (LLC size / number of ways) / page size
 */
#define PG_SIZE 4*1024
/* if color number is changed, GET_COLOR should be modified */
#define COLOR_NUM 64
/* 2GB RAM for coloring */
#define RAM_SIZE 2*1024*1024*1024
#define RAM_MIN 1*1024*1024*1024

/* array of colors */
static NODE color_lists[COLOR_NUM];
/* 
 * used when filling in memory pool
 * page of unwanted color should not be freed before pool is full
 * otherwise, it may be reallocated to us again and again
 */
static NODE page_buf;
/* locks for each color list */
static spinlock_t color_locks[COLOR_NUM];

#ifdef HOT_COLOR
/* global color hotness */
static unsigned long color_hots[COLOR_NUM];
static spinlock_t hot_lock;
#endif

static struct file_operations proc_operations;
static struct proc_dir_entry *proc_entry;


#define MY_CHECK_ALL      _IOW(0, 0, long)
#define MY_CHECK_ONE      _IOW(0, 1, long)
#define MY_CHECK_RESERVE  _IOW(0, 2, long)

#ifdef ROUND_ROBIN
/* current color */
static int color_index;
static spinlock_t index_lock;
#define COLOR_QUOTA 16
#endif




/* *********Utilities********* */
#define GET_COLOR(pfn) (pfn & 0x3F)


/* 'printk' version that prints to active tty. */
static void my_printk(char *string) {

  struct tty_struct *my_tty;

  my_tty = current->signal->tty;

  if (my_tty != NULL) {
    (*my_tty->driver->ops->write)(my_tty, string, strlen(string));
    (*my_tty->driver->ops->write)(my_tty, "\015\012", 2);
  }
}

static void init_check(void) {

  int i, j;
  int pg_num = RAM_MIN / (COLOR_NUM * PG_SIZE);
  for(i = 0; i < COLOR_NUM; i++) {
    if((int)(color_lists[i].data) != pg_num) {
      printk(KERN_ERR "color %d not full: %d pages\n", i, (int)(color_lists[i].data));
    }

    NODE *cur = color_lists[i].next;
    int flag = 0;
    for(j = 0; j < pg_num; j++) {
      if(GET_COLOR(page_to_pfn((struct page *)(cur->data))) != i)
        flag = 1;
    }

    if(flag) {
      printk(KERN_ERR "color %d has pages of different colors\n", i);
    }
  }
}

static void check_lists(void) {

  int i, flag = 0;
  for(i = 0; i < COLOR_NUM; i++) {
    if((int)(color_lists[i].data) != 0) {
      flag = 1;
      printk(KERN_ERR "color not freed: %d\n", i);
    }
  }
  if(flag) my_printk("Memory pool not freed completely!\n");
}


static void free_list_pgs(NODE *list) {

  NODE *node;
  while(1) {
    node = list_remove(list);
    if(node == NULL) break;
    __free_page((struct page *)(node->data));
    kfree(node);
  }
}

struct page *alloc_colored_page(struct mm_struct *mm);
void get_color_set(struct mm_struct *mm);
int debug_ioctl(struct inode *inode, struct file *file,
                unsigned int cmd, unsigned long arg);
HNode *get_coldest(unsigned long *arr, int n, int k);

/* *********Allocator********* */

static int __init alloc_init(void) {

  proc_operations.ioctl = debug_ioctl;

  proc_entry = create_proc_entry("alloc", 0444, NULL);
  if(!proc_entry) {
    my_printk("Error creating /proc entry.\n");
    return 1;
  }

  proc_entry->proc_fops = &proc_operations;

  /* fill in memory pool */
  int pg_num = RAM_SIZE / (COLOR_NUM * PG_SIZE);
  int pg_min = RAM_MIN / (COLOR_NUM * PG_SIZE);
  struct page *new_pg;

  /* initialize locks */
  int k;
  for(k = 0; k < COLOR_NUM; k++)
    color_locks[k] = SPIN_LOCK_UNLOCKED;

#ifdef ROUND_ROBIN
  index_lock = SPIN_LOCK_UNLOCKED;
  color_index = 0;
#endif

#ifdef HOT_COLOR
  hot_lock = SPIN_LOCK_UNLOCKED;
  for(k = 0; k < COLOR_NUM; k++)
    color_hots[k] = 0;
#endif

#if 0
  int i, j;
  for(i = 0; i < COLOR_NUM; i++) {
    for(j = 0; j < pg_num; j++) {
      new_pg = alloc_page(__GFP_HIGHMEM | __GFP_MOVABLE | __GFP_ZERO);
      if(new_pg == NULL) {
        my_printk("Fails to alloc a page!\n");
        return 0;
      }
        
      if(!list_insert(&color_lists[i], new_pg)) {
        my_printk("Fails to alloc a node!\n");
        return 0;
      }
    }
  }
#else

  int count = 0, color, num;
  unsigned long frame;
  int flag = 0;

  while(count != COLOR_NUM) {
    new_pg = alloc_page(__GFP_HIGHMEM | __GFP_MOVABLE | __GFP_ZERO);
    if(new_pg == NULL) {
      if(flag == COLOR_NUM) break;

      my_printk("Fails to alloc a page!\n");
      return 1;
    }

    frame = page_to_pfn(new_pg);
    color = GET_COLOR(frame);

    num = (int)(color_lists[color].data);
    if(num >= pg_num) { /* color list is full */
      if(!list_insert(&page_buf, new_pg)) {
        my_printk("Fails to alloc a node!\n");
        return 1;
      }
    }
    else {
      if(!list_insert(&color_lists[color], new_pg)) {
        my_printk("Fails to alloc a node!\n");
        return 1;
      }

      if((int)(color_lists[color].data) == pg_num) count++;

      if((int)(color_lists[color].data) == pg_min) flag++;
    }
  }

  /* free page buffer */
  free_list_pgs(&page_buf);

#ifdef NEW_ALLOC
  /* load functions */
  colored_alloc = alloc_colored_page;
  assign_colors = get_color_set;

  my_printk("Defined!");
#endif

#endif  

#ifdef ALLOC_DEBUG
  init_check();
#endif

  my_printk("Allocator loaded!");
  return 0;
}


/* memory allocated to user processes is not freed back to this module but to Buddy system */
static void __exit alloc_cleanup(void) {

  remove_proc_entry("alloc", NULL);

  /* free memory pool */
  int i;
  for(i = 0; i < COLOR_NUM; i++) {
    free_list_pgs(&color_lists[i]);
  }

#ifdef NEW_ALLOC
  /* unload functions */
  colored_alloc = NULL;
  assign_colors = NULL;
#endif

#ifdef ALLOC_DEBUG
  check_lists();
#endif

  my_printk("Allocator unloaded!");
}

static struct page *internal_alloc_page(int color) {

  if(color >= COLOR_NUM || color < 0) {
    my_printk("Invalid color!\n");
    return NULL;
  }

  unsigned long flags;
  spin_lock_irqsave(&color_locks[color], flags);

  int num = (int)(color_lists[color].data);
  /* running out of memory */
  if(num <= 0) {
    spin_unlock_irqrestore(&color_locks[color], flags);
    printk(KERN_ERR "color %d: out of memory!\n", color);
    return NULL;
  }

  NODE *node = list_remove(&color_lists[color]);

  spin_unlock_irqrestore(&color_locks[color], flags);

  struct page *new_pg = (struct page *)(node->data);
  kfree(node);
  if(new_pg == NULL)
    my_printk("bug for alloc!\n");

  return new_pg;
}


/* called by page fault handler */
struct page *alloc_colored_page(struct mm_struct *mm) {

  int level, index;
  struct page *new_pg;
  int counter = 0;
  struct color_set *set_ptr;
  unsigned long flags;

  if(mm == NULL) {
    my_printk("%s: mm is invalid!\n");
    return NULL;
  }

  if(mm->color_num == 0) return NULL;
	
  spin_lock_irqsave(&mm->cur_lock, flags);

  do {
    level = mm->color_cur / COLOR_BASE;
    set_ptr = &(mm->my_colors);

    while(level != 0) {
      if(!(set_ptr = set_ptr->next)) {
        my_printk("bug for color assignment!\n");
	spin_unlock_irqrestore(&mm->cur_lock, flags);
	return NULL;
      }
      level--;
    }

    index = mm->color_cur % COLOR_BASE;
    new_pg = internal_alloc_page(set_ptr->colors[index]);
    mm->color_cur = (mm->color_cur + 1) % (mm->color_num);
    counter++;
    /* if color is out of memory, try another one */
  } while(new_pg == NULL && counter < mm->color_num);

  spin_unlock_irqrestore(&mm->cur_lock, flags);

  return new_pg; 
}


/* called by do_execve */
void get_color_set(struct mm_struct *mm) {

  if(mm == NULL) {
    my_printk("Invalid mm argument!\n");
    return;
  }

#if 0
  /* placeholder */
  mm->color_num = 0;
#else

#ifdef ROUND_ROBIN
  int index = 0, counter = 0;
  unsigned long flags;
  struct color_set *set_ptr= &(mm->my_colors);

  spin_lock_irqsave(&index_lock, flags);

  do {
    if(index < COLOR_BASE) {
      set_ptr->colors[index] = color_index;
      set_ptr->hotness[index] = 0;
      index++;
      counter++;
      color_index = (color_index + 1) % COLOR_NUM;
    }
    else {
      index = 0;
      if(!(set_ptr->next = kmalloc(sizeof(struct color_set), GFP_KERNEL))) {
        my_printk("color_set fails to be created!\n");
        break;
      }
      set_ptr = set_ptr->next;
      continue;
    }
  } while(counter < COLOR_QUOTA);

  spin_unlock_irqrestore(&index_lock, flags);

  set_ptr->next = NULL;
  mm->color_num = counter;
  mm->color_cur = 0;

#endif

#ifdef HOT_COLOR
  int index = 0, counter = 0;
  unsigned long flags;
  struct color_set *set_ptr = &(mm->my_colors);

  spin_lock_irqsave(&hot_lock, flags);

  HNode *assignment = get_coldest(color_hots, COLOR_NUM, COLOR_QUOTA);

  spin_unlock_irqrestore(&hot_lock, flags);

  do {
    if(index < COLOR_BASE) {
      set_ptr->colors[index] = assignment[counter + 1].index;
      set_ptr->hotness[index] = 0;
      index++;
      counter++;
    }
    else {
      index = 0;
      if(!(set_ptr->next = kmalloc(sizeof(struct color_set), GFP_KERNEL))) {
        my_printk("color_set fails to be created!\n");
        break;
      }
      set_ptr = set_ptr->next;
      continue;
    }
  } while(counter < COLOR_QUOTA);

  set_ptr->next = NULL;
  mm->color_num = counter;
  mm->color_cur = 0;

  kfree(assignment);

#endif

#ifdef ALLOC_DEBUG
  printk(KERN_ERR "%s (pid %d tgid %d colors %d): mm addr %u!\n", mm->owner->comm,
    mm->owner->pid, mm->owner->tgid, mm->color_num, (unsigned int)mm);
#endif
#endif
}

/* get k coldest colors */
HNode *get_coldest(unsigned long *arr, int n, int k) {

  if(arr == NULL) {
    my_printk("Invalid array!\n");
    return NULL;
  }

  if(k > n) {
    my_printk("k too large!\n");
    return NULL;
  }

  HNode *heap = kmalloc((k + 1) * sizeof(HNode), GFP_KERNEL);
  if(heap == NULL) {
    my_printk("Heap kmalloc fails!\n");
    return NULL;
  }

  int i;
  for(i = 0; i < k; i++) {
    heap[i + 1].data = arr[i];
    heap[i + 1].index = i;
  }

  HeapBuild(heap, k);

  for( ; i < n; i++) {
    if(arr[i] < heap[1].data) {
      heap[1].data = arr[i];
      heap[1].index = i;
      HeapAdjust(heap, 1, k);
    }
  }

  return heap;
}

/* ioctl entry point, debugging tool */
int debug_ioctl(struct inode *inode, struct file *file,
                        unsigned int cmd, unsigned long arg) {

#ifdef NEW_ALLOC
  struct task_struct *p;
  struct mm_struct *mm;
  int counter, index, i;
  struct color_set *set_ptr;

  if(cmd == MY_CHECK_ALL) {
    read_lock(&tasklist_lock);

    for_each_process(p) {
      mm = p->mm;
      /* ignore kernel threads and irrelevant processes */
      if(mm != NULL && mm->color_num > 0) {
        printk(KERN_ERR "%s (pid %d, tgid %d, frss %d, arss %d, mm addr %u): ", p->comm,
          p->pid, p->tgid, mm->_file_rss, mm->_anon_rss, (unsigned int)mm);

        counter = 0;
        index = 0;
        set_ptr = &(mm->my_colors);

        do {
          if(index < COLOR_BASE) { 
            printk(KERN_ERR "%d ", set_ptr->colors[index]);

            index++;
            counter++;
          }
          else {
            index = 0;
            if(!(set_ptr = set_ptr->next)) {
              my_printk("bug in color_set!\n");
              break;
            }
            continue;
          }
        } while(counter < mm->color_num);

        printk(KERN_ERR " current: %d\n", mm->color_cur);
      }
    }

    read_unlock(&tasklist_lock);
  }
  else if(cmd == MY_CHECK_ONE) {
    rcu_read_lock();

    /* look up thread by pid */
    p = find_task_by_vpid((pid_t)arg);

    rcu_read_unlock();

    if(p == NULL) {
      my_printk("No process found!\n");
    }
    else if(p->mm == NULL) {
      my_printk("PID belongs to kernel thread!\n");
    }
    else if(p->mm->color_num == 0) {
      my_printk("No color assigned to it!\n");
    }
    else {
      mm = p->mm;
      counter = 0;
      index = 0;
      set_ptr = &(mm->my_colors);

      printk(KERN_ERR "Process: ");
      do {
        if(index < COLOR_BASE) {
          printk(KERN_ERR "%d ", set_ptr->colors[index]);

          index++;
          counter++;
        }
        else {
          index = 0;
          if(!(set_ptr = set_ptr->next)) {
            my_printk("bug in color_set!\n");
            break;
          }
          continue;
        }
      } while(counter < mm->color_num);

      printk(KERN_ERR " current: %d\n", mm->color_cur);
    }

    //XXX: rcu_read_unlock() was here
  }
  else if(cmd == MY_CHECK_RESERVE) {
    printk(KERN_ERR "Color statistic: ");

    for(i = 0; i < COLOR_NUM; i++)
      printk(KERN_ERR "color %d (%d) ", i, (int)(color_lists[i].data));

    printk(KERN_ERR "\n");
  }
  else {
    my_printk("Invalid input command!\n");
    return -1;
  }

#endif

  return 0;
}



module_init(alloc_init);
module_exit(alloc_cleanup);

/* vi: set et sw=2 sts=2: */
