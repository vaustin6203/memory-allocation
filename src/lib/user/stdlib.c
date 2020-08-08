#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "syscall.h"

struct heap_block {
	size_t size;
	bool free; 
	struct heap_block *next;
	struct heap_block *prev;
	uint8_t block[0];
};

struct heap_block *heap = NULL;

void*
malloc (size_t size)
{
  /* Homework 5, Part B: YOUR CODE HERE */
  if (size == 0) {
  	return NULL;
  } else if (heap == NULL) {
  	heap = sbrk(sizeof(struct heap_block) + size);
  	if (heap != (void *) -1) {
  		heap->size = size;
  		heap->free = false;
  		heap->next = NULL;
  		heap->prev = NULL;
  		return &heap->block[0];
  	}
  	return NULL;
  }
  
  struct heap_block *curr = heap;
  struct heap_block *temp; 
  struct heap_block *new_block;
  while(curr != NULL) {
  	if (curr->size >= size && curr->free == true) {
  		if (curr->size - size >= sizeof(struct heap_block) + 1) {
  			curr->free = false;
  			curr->size = size; 
  			temp = curr->next;
  			new_block = &curr->block[0] + size;
  			curr->next = new_block;
  			new_block->size = curr->size - size;
  			new_block->free = true; 
  			new_block->next = temp; 
  			new_block->prev = curr;
  			return &curr->block[0];
  		} else {
  			curr->free = false;
  			return &curr->block[0];
  		}
  	}
  	if(curr->next == NULL) {
  		temp = curr;
  	}
  	curr = curr->next;
  }
  new_block = sbrk(size + sizeof(struct heap_block));
  if (new_block == (void *) -1) {
  	return NULL;
  }
  
  temp->next = new_block;
  new_block->size = size;
  new_block->free = false; 
  new_block->prev = temp; 
  new_block->next = NULL;
  return &new_block->block[0]; 
}

struct heap_block* find_first_free_block(struct heap_block *block) {
	struct heap_block *curr = block; 
	while(curr != NULL) {
		if(curr->prev == NULL) {
			return curr;
		} else if (curr->prev->free == true) {
			curr = curr->prev;
		} else {
			return curr;
		}
	}
	return curr->prev;
}

void free_blocks(struct heap_block *block) {
	struct heap_block *first_free = find_first_free_block(block);
	size_t total_size = 0;
	struct heap_block *curr = first_free;
	while(curr != NULL) {
		total_size += curr->size;
		if (curr->next == NULL || curr->next->free == false) {
			first_free->next = curr->next;
			break; 
		} 
		curr = curr->next; 
	}
}

void free (void* ptr)
{
  /* Homework 5, Part B: YOUR CODE HERE */
  if (ptr != NULL) {
  	struct heap_block *curr = heap;
  	while (curr != NULL) {
  		if (&curr->block[0] == ptr) {
  			curr->free = true; 
  			free_blocks(curr);
  			break; 
  		}
  		curr = curr->next; 
  	}
  }
}

void* calloc (size_t nmemb, size_t size)
{
  /* Homework 5, Part B: YOUR CODE HERE */
  size_t total_size = size * nmemb;
  void *block = malloc(total_size);
  if (block == NULL) {
  	return NULL;
  }
  memset(block, 0, total_size);
  return block;
}

void* realloc (void* ptr, size_t size)
{
  /* Homework 5, Part B: YOUR CODE HERE */
  if (size == 0) {
  	free(ptr);
  	return NULL;
  } else if (ptr == NULL) {
  	return malloc(size);
  }

  void *h_block = malloc(size);
  if (h_block == NULL) {
  	return NULL;
  }
  memcpy(h_block, ptr, size);
  free(ptr);
  return h_block;
}
