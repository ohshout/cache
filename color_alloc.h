/* --ADDED-- */
#ifndef _LINUX_COLOR_ALLOC_H
#define _LINUX_COLOR_ALLOC_H

#define NEW_ALLOC

#ifdef NEW_ALLOC
#define COLOR_BASE 64

struct color_set {
	int colors[COLOR_BASE];
};

struct color_map {
	/* XXX: hard-coded 64 colors */
	unsigned int data[2];
};

#define MAP_SET_COLOR(map, n) \
do {	\
	if(n < 32) map.data[0] = map.data[0] | (1 << n);	\
	else map.data[1] = map.data[1] | (1 << (n - 32));	\
} while(0)

#define MAP_IS_OVERLAP(map1, map2) \
((map1.data[0] & map2.data[0]) | (map1.data[1] & map2.data[1]))

#endif

#endif
