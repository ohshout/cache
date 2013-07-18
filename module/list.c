#include <linux/kernel.h>
#include "list.h"


/* insert a node at the end and return it */
NODE *list_insert(LIST *list, void *data, NODE *node) {

#ifdef MY_LIST_DEBUG
  if(list == NULL || node == NULL) {
    printk("%s: invalid input!\n", __func__);
    return NULL;
  } 
#endif

  node->data = data;
  node->next = NULL;
  /* empty list */
  if(list->num == 0) {
    list->head = node;
    list->tail = node;
  }
  else {
    list->tail->next = node;
    list->tail = node;
  }
  
  list->num = list->num + 1;

  return node;
}


/* remove the first node and return it */
NODE *list_remove(LIST *list) {

#ifdef MY_LIST_DEBUG
  if(list == NULL) {
    printk("%s: invalid input!\n", __func__);
    return NULL;
  }
#endif

  NODE *node = list->head;
  if(!node) {
#ifdef MY_LIST_DEBUG
    printk("%s: empty list!\n", __func__);
#endif
    return NULL;
  }

  if(list->num == 1) {
    list->head = NULL;
    list->tail = NULL;
  }
  else {
    list->head = node->next;
  }

  list->num = list->num - 1;
  
  return node;
}


/* vi: set et sw=2 sts=2: */
