#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include <sys/mman.h>
#include "myalloc.h"

#define INITIAL_SIZE (1 << 30)

/*** DATA STRUCTURES ***/

typedef struct {
	size_t block_size;
	char block_used;
} block_header;

/*** FUNCTION PROTOTYPES ***/

void *initialize_memory();
void *find_free_block(size_t size);

void allocate_block(void *block_ptr, size_t size);
void free_block(void *block_ptr);

void write_free_block(void *ptr, size_t size);
void write_used_block(void *ptr, size_t size);

void *get_content_pointer(void *block_ptr);
void *get_block_pointer(void *content_ptr);
size_t get_content_size(void *block_ptr);
char is_block_used(void *block_ptr);
void *get_next_block(void *block_ptr);

size_t get_block_size(void *block_ptr);

/*** GLOBAL VARIABLES ***/

static void *start_ptr = NULL;

/*** LIBRARY FUNCTIONS ***/

void *myalloc(int size) {
	if (start_ptr == NULL) {
		// printf("initialising memory...\n");
		start_ptr = initialize_memory();
		// printf("initialised memory\n");

		if (start_ptr == NULL) {
			return NULL;
		}
	}

	// printf("looking for a free block for %d bytes...\n", size);
	void* free_block_ptr = find_free_block(size);
	// printf("found a free block: %p\n", free_block_ptr);

	if (free_block_ptr == NULL) {
		return NULL;
	}

	// printf("allocating the free block...\n");
	allocate_block(free_block_ptr, size);
	// printf("allocated the free block\n");

	return get_content_pointer(free_block_ptr);
}

void myfree(void *ptr){
	free_block(ptr);
}

/*** INITIALISATION FUNCTIONS ***/

void *initialize_memory() {
	void* ptr = mmap(0, INITIAL_SIZE, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

	if (ptr == MAP_FAILED) {
		return NULL;
	}

	write_free_block(ptr, INITIAL_SIZE);

	return ptr;
}

/*** SEARCH FUNCTIONS ***/

void *find_free_block(size_t size) {
	void *end_ptr = start_ptr + INITIAL_SIZE;
	void *block_ptr = start_ptr;

	// printf("- end is %p\n", end_ptr);

	while (block_ptr < end_ptr) {
		// printf("- checking block %p size %d used %d\n", block_ptr, get_content_size(block_ptr), is_block_used(block_ptr));
		if (!is_block_used(block_ptr) && get_content_size(block_ptr) >= size) {
			return block_ptr;
		} else {
			block_ptr = get_next_block(block_ptr);
		}
	}

	// printf("- no free blocks found\n");

	return NULL;
}

/*** ALLOCATION FUNCTIONS ***/

void allocate_block(void *block_ptr, size_t used_content_size) {
	assert(!is_block_used(block_ptr));
	assert(get_content_size(block_ptr) >= used_content_size);

	size_t original_block_size = get_block_size(block_ptr);
	size_t original_content_size = get_content_size(block_ptr);

	size_t used_block_size = used_content_size + sizeof(block_header);
	write_used_block(block_ptr, used_block_size);

	if (original_content_size > used_content_size) {
		size_t free_block_size = original_block_size - used_block_size;
		write_free_block(block_ptr + used_block_size, free_block_size);
	}
}

/*** FREEING FUNCTIONS ***/

void free_block(void *content_ptr) {
	void *block_ptr = get_block_pointer(content_ptr);
	size_t size = get_block_size(block_ptr);
	write_free_block(block_ptr, size);
	// printf("freed block %p size %d\n", block_ptr, size);
}

/*** BLOCK HELPER FUNCTIONS ***/

void write_free_block(void *ptr, size_t size) {
	block_header *header_ptr = ptr;
	header_ptr->block_size = size;
	header_ptr->block_used = 0;
}

void write_used_block(void *ptr, size_t size) {
	block_header *header_ptr = ptr;
	header_ptr->block_size = size;
	header_ptr->block_used = 1;
}

void *get_content_pointer(void *block_ptr) {
	return block_ptr + sizeof(block_header);
}

void *get_block_pointer(void *content_ptr) {
	return content_ptr - sizeof(block_header);
}

size_t get_block_size(void *block_ptr) {
	block_header *header_ptr = block_ptr;
	return header_ptr->block_size;
}

size_t get_content_size(void *block_ptr) {
	return get_block_size(block_ptr) - sizeof(block_header);
}

char is_block_used(void *block_ptr) {
	block_header *header_ptr = block_ptr;
	return header_ptr->block_used;
}

void *get_next_block(void *block_ptr) {
	return block_ptr + get_block_size(block_ptr);
}
