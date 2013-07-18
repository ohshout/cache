#ifndef _MY_LIST_H_
#define _MY_LIST_H_

//#define MY_LIST_DEBUG

typedef struct node_s {
  void *data;
  struct node_s *next;
} NODE;

typedef struct _list {
  int num;
  NODE *head, *tail;
} LIST;


NODE *list_insert(LIST *list, void *data, NODE *node);
NODE *list_remove(LIST *list);


#endif

/* vi: set et sw=2 sts=2: */
