#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/mman.h>
#include "myalloc.h"

#define INITIAL_SIZE (1 << 30)

/*** DATA STRUCTURES ***/

typedef struct {
	size_t block_size;
	bool block_used;
	bool previous_used;
	bool last_block;
} block_header;

typedef struct {
	size_t block_size;
} block_footer;

/*** FUNCTION PROTOTYPES ***/

void *initialize_memory();
void *find_free_block(size_t size);

void allocate_block(void *block_ptr, size_t size);
void free_block(void *block_ptr);

void write_free_block(void *ptr, size_t size, bool previous_used,
	bool last_block);
void write_used_block(void *ptr, size_t size, bool previous_used,
	bool last_block);
void set_previous_used(void *block_ptr, bool value);

void *get_content_pointer(void *block_ptr);
void *get_block_pointer(void *content_ptr);
size_t get_content_size(void *block_ptr);
size_t get_block_size(void *block_ptr);
bool is_block_used(void *block_ptr);
bool is_previous_used(void* block_ptr);
bool is_next_used(void *block_ptr);
bool is_last_block(void *block_ptr);
void *get_previous_block(void *block_ptr);
void *get_next_block(void *block_ptr);

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

	write_free_block(ptr, INITIAL_SIZE, true, true);

	return ptr;
}

/*** SEARCH FUNCTIONS ***/

void *find_free_block(size_t size) {
	void *block_ptr = start_ptr;

	// printf("- end is %p\n", end_ptr);

	do {
		// printf("- checking block %p size %d used %d\n", block_ptr, get_content_size(block_ptr), is_block_used(block_ptr));
		if (!is_block_used(block_ptr) && get_content_size(block_ptr) >= size) {
			return block_ptr;
		} else {
			block_ptr = get_next_block(block_ptr);
		}
	} while (block_ptr != NULL);

	// printf("- no free blocks found\n");

	return NULL;
}

/*** ALLOCATION FUNCTIONS ***/

void allocate_block(void *block_ptr, size_t used_content_size) {
	assert(!is_block_used(block_ptr));
	assert(get_content_size(block_ptr) >= used_content_size);

	size_t original_block_size = get_block_size(block_ptr);
	size_t original_content_size = get_content_size(block_ptr);
	bool original_last_block = is_last_block(block_ptr);
	bool original_previous_used = is_previous_used(block_ptr);

	size_t used_block_size = used_content_size + sizeof(block_header);

	if (original_content_size > used_content_size) {
		// if the used block is bigger than needed, split it into a used
		// and a free block

		write_used_block(block_ptr, used_block_size, original_previous_used, false);

		void *free_block_ptr = block_ptr + used_block_size;
		size_t free_block_size = original_block_size - used_block_size;
		write_free_block(free_block_ptr, free_block_size, true, original_last_block);

		// updating the next block's previous_used is not neccessary, because
		// it's already set to false (next block's previous block is the block
		// we're allocating, which was free)
	} else {
		// used block is exactly the size we need
		write_used_block(block_ptr, used_block_size, original_previous_used, original_last_block);

		// we need to update next block's previous_used to true
		void *next_block = get_next_block(block_ptr);

		if (next_block != NULL) {
			set_previous_used(next_block, true);
		}
	}
}

/*** FREEING FUNCTIONS ***/

void free_block(void *content_ptr) {
	void *block_ptr = get_block_pointer(content_ptr);

	assert(is_block_used(block_ptr));

	bool previous_used = is_previous_used(block_ptr);
	bool next_used = is_next_used(block_ptr);
	bool last_block = is_last_block(block_ptr);

	void *new_block_ptr = block_ptr;
	size_t new_block_size = get_block_size(block_ptr);
	bool new_previous_used = previous_used;
	bool new_last_block = last_block;

	if (!previous_used) {
		void *previous_block = get_previous_block(block_ptr);

		new_block_ptr = previous_block;
		new_block_size += get_block_size(previous_block);
		new_previous_used = is_previous_used(previous_block);
	}

	if (!next_used) {
		void *next_block = get_next_block(block_ptr);
		new_block_size += get_block_size(next_block);
		new_last_block = is_last_block(next_block);
	}

	write_free_block(new_block_ptr, new_block_size, new_previous_used, new_last_block);

	void *next_block = get_next_block(new_block_ptr);

	if (next_block != NULL) {
		set_previous_used(next_block, false);
	}

	// printf("freed block %p\n", block_ptr);
}

/*** BLOCK HELPER FUNCTIONS ***/

void write_free_block(void *ptr, size_t size, bool previous_used,
		bool last_block) {
	block_header *header_ptr = ptr;
	header_ptr->block_size = size;
	header_ptr->block_used = false;
	header_ptr->previous_used = previous_used;
	header_ptr->last_block = last_block;

	block_footer *footer_ptr = ptr + (size - sizeof(block_footer));
	footer_ptr->block_size = size;
}

void write_used_block(void *ptr, size_t size, bool previous_used,
		bool last_block) {
	block_header *header_ptr = ptr;
	header_ptr->block_size = size;
	header_ptr->block_used = true;
	header_ptr->previous_used = previous_used;
	header_ptr->last_block = last_block;
}

void set_previous_used(void *block_ptr, bool value) {
	block_header *header_ptr = block_ptr;
	header_ptr->previous_used = value;
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

bool is_block_used(void *block_ptr) {
	block_header *header_ptr = block_ptr;
	return header_ptr->block_used;
}

bool is_previous_used(void *block_ptr) {
	block_header *header_ptr = block_ptr;
	return header_ptr->previous_used;
}

bool is_next_used(void *block_ptr) {
	void *next_block_ptr = get_next_block(block_ptr);

	if (next_block_ptr != NULL) {
		return is_block_used(next_block_ptr);
	} else {
		return true;
	}
}

bool is_last_block(void *block_ptr) {
	block_header *header_ptr = block_ptr;
	return header_ptr->last_block;
}

void *get_next_block(void *block_ptr) {
	if (!is_last_block(block_ptr)) {
		return block_ptr + get_block_size(block_ptr);
	} else {
		return NULL;
	}
}

void *get_previous_block(void *block_ptr) {
	if (!is_previous_used(block_ptr)) {
		block_footer *footer_ptr = block_ptr - sizeof(block_footer);
		return block_ptr - footer_ptr->block_size;
	} else {
		return NULL;
	}
}
