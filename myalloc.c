#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include "myalloc.h"

#define MIN_REGION_SIZE (1 << 30)

#define BLOCK_SIZE_MULTIPLE (8)
#define BLOCK_HEADER_BLOCK_SIZE (~7)
#define BLOCK_HEADER_BLOCK_USED (4)
#define BLOCK_HEADER_PREVIOUS_USED (2)
#define BLOCK_HEADER_LAST_BLOCK (1)

/*** DATA STRUCTURES ***/

typedef size_t block_header;

typedef struct {
	size_t block_size;
} block_footer;

typedef struct {
	void *next_region;
	size_t region_size;
	int used_blocks_num;
} region_header;

/*** FUNCTION PROTOTYPES ***/

void *get_free_block(size_t size);
void *find_free_block_in_region(void *region_ptr, size_t size);
bool is_better_block(void *block_ptr, void *best_block_ptr);

void allocate_block(void *block_ptr, size_t size);
void free_block(void *block_ptr);

void write_free_block(void *ptr, size_t size, bool previous_used,
	bool last_block);
void write_used_block(void *ptr, size_t size, bool previous_used,
	bool last_block);
void write_block_header(void *ptr, size_t size, bool block_used,
	bool previous_used, bool last_block);
void write_block_footer(void *ptr, size_t size);
void set_previous_used(void *block_ptr, bool value);

void *get_content_pointer(void *block_ptr);
void *get_block_pointer(void *content_ptr);
size_t get_block_size(void *block_ptr);
size_t get_block_size_from_content_size(size_t content_size);
bool is_block_used(void *block_ptr);
bool is_previous_used(void* block_ptr);
bool is_next_used(void *block_ptr);
bool is_last_block(void *block_ptr);
void *get_previous_block(void *block_ptr);
void *get_next_block(void *block_ptr);

void *create_region(size_t size);
void destroy_region(void *region_ptr);
void *get_first_block(void *region_ptr);
void *get_next_region(void *region_ptr);
void set_next_region(void *region_ptr, void *next_region_ptr);
bool is_block_in_region(void *block_ptr, void *region_ptr);
void *get_block_region(void *block_ptr);
bool is_region_empty(void *region_ptr);
void update_region_used_blocks_num(void *region_ptr, int delta);

size_t round_up_size(size_t size, size_t multiple);

/*** GLOBAL VARIABLES ***/

static void *first_region_ptr = NULL;

/*** LIBRARY FUNCTIONS ***/

void *myalloc(int size) {
	// printf("looking for a free block for %d bytes...\n", size);
	void* free_block_ptr = get_free_block(size);
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

/*** SEARCH FUNCTIONS ***/

void *get_free_block(size_t content_size) {
	size_t block_size = get_block_size_from_content_size(content_size);

	void *region_ptr = first_region_ptr;
	void *last_region_ptr = NULL;
	void *best_block_ptr = NULL;

	while (region_ptr != NULL) {
		last_region_ptr = region_ptr;

		// printf("checking region %p\n", region_ptr);
		void *found_block_ptr = find_free_block_in_region(region_ptr, block_size);

		if (found_block_ptr != NULL) {
			if (get_block_size(found_block_ptr) == block_size) {
				// perfect block found, no need to go further
				return found_block_ptr;
			} else if (is_better_block(found_block_ptr, best_block_ptr)) {
				best_block_ptr = found_block_ptr;
			}
		}

		region_ptr = get_next_region(region_ptr);
	}

	if (best_block_ptr != NULL) {
		return best_block_ptr;
	} else {
		void *free_region = create_region(block_size);

		if (free_region == NULL) {
			return NULL;
		}

		if (first_region_ptr == NULL) {
			first_region_ptr = free_region;
		}

		if (last_region_ptr != NULL) {
			set_next_region(last_region_ptr, free_region);
		}

		// printf("created region %p\n", free_region);
		return get_first_block(free_region);
	}
}

void *find_free_block_in_region(void *region_ptr, size_t block_size) {
	void *block_ptr = get_first_block(region_ptr);
	void *best_block_ptr = NULL;

	do {
		// printf("- checking block %p size %d used %d\n", block_ptr, get_content_size(block_ptr), is_block_used(block_ptr));
		if (!is_block_used(block_ptr)) {
			if (get_block_size(block_ptr) == block_size) {
				// perfect block found, no need to go further
				return block_ptr;
			} else if (
				get_block_size(block_ptr) > block_size &&
				is_better_block(block_ptr, best_block_ptr)
			) {
				best_block_ptr = block_ptr;
			}
		}

		block_ptr = get_next_block(block_ptr);
	} while (block_ptr != NULL);

	// printf("- no free blocks found\n");

	return best_block_ptr;
}

bool is_better_block(void *block_ptr, void *best_block_ptr) {
	return best_block_ptr == NULL ||
		get_block_size(block_ptr) < get_block_size(best_block_ptr);
}

/*** ALLOCATION FUNCTIONS ***/

void allocate_block(void *block_ptr, size_t used_content_size) {
	size_t used_block_size = get_block_size_from_content_size(used_content_size);

	assert(!is_block_used(block_ptr));
	assert(get_block_size(block_ptr) >= used_block_size);

	size_t original_block_size = get_block_size(block_ptr);
	bool original_last_block = is_last_block(block_ptr);
	bool original_previous_used = is_previous_used(block_ptr);

	if (original_block_size > used_block_size) {
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

	void *region_ptr = get_block_region(block_ptr);
	update_region_used_blocks_num(region_ptr, 1);
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

	void *region_ptr = get_block_region(block_ptr);
	update_region_used_blocks_num(region_ptr, -1);

	if (is_region_empty(region_ptr)) {
		destroy_region(region_ptr);
	}

	// printf("freed block %p\n", block_ptr);
}

/*** BLOCK HELPER FUNCTIONS ***/

void write_free_block(void *ptr, size_t size, bool previous_used,
		bool last_block) {
	write_block_header(ptr, size, false, previous_used, last_block);
	write_block_footer(ptr, size);
}

void write_used_block(void *ptr, size_t size, bool previous_used,
		bool last_block) {
	write_block_header(ptr, size, true, previous_used, last_block);
}

void write_block_header(void *ptr, size_t size, bool block_used,
		bool previous_used, bool last_block) {
	block_header *header_ptr = ptr;

	// write all but the last three bits of size
	// the three unused bits are set to zero
	(*header_ptr) = size & BLOCK_HEADER_BLOCK_SIZE;

	if (block_used) {
		// turn on the block_used flag
		(*header_ptr) |= BLOCK_HEADER_BLOCK_USED;
	}

	if (previous_used) {
		// turn on the previous_used flag
		(*header_ptr) |= BLOCK_HEADER_PREVIOUS_USED;
	}

	if (last_block) {
		// turn on the last_block flag
		(*header_ptr) |= BLOCK_HEADER_LAST_BLOCK;
	}
}

void write_block_footer(void *ptr, size_t size) {
	block_footer *footer_ptr = ptr + (size - sizeof(block_footer));
	footer_ptr->block_size = size;
}

void *get_content_pointer(void *block_ptr) {
	return block_ptr + sizeof(block_header);
}

void *get_block_pointer(void *content_ptr) {
	return content_ptr - sizeof(block_header);
}

size_t get_block_size(void *block_ptr) {
	block_header *header_ptr = block_ptr;
	return (*header_ptr) & BLOCK_HEADER_BLOCK_SIZE;
}

bool is_block_used(void *block_ptr) {
	block_header *header_ptr = block_ptr;
	return (*header_ptr) & BLOCK_HEADER_BLOCK_USED;
}

bool is_previous_used(void *block_ptr) {
	block_header *header_ptr = block_ptr;
	return (*header_ptr) & BLOCK_HEADER_PREVIOUS_USED;
}

void set_previous_used(void *block_ptr, bool value) {
	block_header *header_ptr = block_ptr;

	if (value) {
		(*header_ptr) |= BLOCK_HEADER_PREVIOUS_USED;
	} else {
		(*header_ptr) &= ~BLOCK_HEADER_PREVIOUS_USED;
	}
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
	return (*header_ptr) & BLOCK_HEADER_LAST_BLOCK;
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

size_t get_block_size_from_content_size(size_t content_size) {
	return round_up_size(content_size + sizeof(block_header), BLOCK_SIZE_MULTIPLE);
}

/*** REGION HELPER FUNCTIONS ***/

void *create_region(size_t requested_block_size) {
	if (requested_block_size < MIN_REGION_SIZE) {
		requested_block_size = MIN_REGION_SIZE;
	}

	size_t requested_region_size = requested_block_size + sizeof(region_header);
	size_t region_size = round_up_size(requested_region_size, getpagesize());

	// printf("creating region size %zu\n", region_size);

	void *region_ptr = mmap(0, region_size, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

	if (region_ptr == MAP_FAILED) {
		return NULL;
	}

	region_header *header_ptr = region_ptr;
	header_ptr->next_region = NULL;
	header_ptr->region_size = region_size;
	header_ptr->used_blocks_num = 0;

	void *block_ptr = get_first_block(region_ptr);
	size_t block_size = region_size - sizeof(region_header);
	write_free_block(block_ptr, block_size, true, true);

	// printf("Created new region at %p\n", region_ptr);

	return region_ptr;
}

void destroy_region(void *region_ptr) {
	region_header *header_ptr = region_ptr;

	if (region_ptr == first_region_ptr) {
		first_region_ptr = header_ptr->next_region;
	} else {
		region_header *previous_header_ptr = first_region_ptr;

		while (previous_header_ptr->next_region != region_ptr) {
			previous_header_ptr = previous_header_ptr->next_region;
		}

		assert(previous_header_ptr != NULL);

		previous_header_ptr->next_region = header_ptr->next_region;
	}

	munmap(region_ptr, header_ptr->region_size);

	// printf("Destroyed region at %p\n", region_ptr);
}

void *get_block_region(void *block_ptr) {
	void *region_ptr = first_region_ptr;

	while (region_ptr != NULL) {
		if (is_block_in_region(block_ptr, region_ptr)) {
			return region_ptr;
		}

		region_ptr = get_next_region(region_ptr);
	}

	return NULL;
}

void *get_first_block(void *region_ptr) {
	return region_ptr + sizeof(region_header);
}

void *get_next_region(void *region_ptr) {
	region_header *header_ptr = region_ptr;
	return header_ptr->next_region;
}

void set_next_region(void *region_ptr, void *next_region_ptr) {
	region_header *header_ptr = region_ptr;
	header_ptr->next_region = next_region_ptr;
}

bool is_block_in_region(void *block_ptr, void *region_ptr) {
	region_header *header_ptr = region_ptr;

	void *region_start = region_ptr;
	void *region_end = region_start + header_ptr->region_size;

	return block_ptr > region_start && block_ptr < region_end;
}

bool is_region_empty(void *region_ptr) {
	region_header *header_ptr = region_ptr;
	return header_ptr->used_blocks_num == 0;
}

void update_region_used_blocks_num(void *region_ptr, int delta) {
	region_header *header_ptr = region_ptr;
	header_ptr->used_blocks_num += delta;

	// printf("Updated used blocks num to %d\n", header_ptr->used_blocks_num);
}

/*** GENERAL HELPER FUNCTIONS ***/

size_t round_up_size(size_t size, size_t multiple) {
	size_t remainder = size % multiple;

	if (remainder == 0) {
		return size;
	} else {
		return size + multiple - remainder;
	}
}
