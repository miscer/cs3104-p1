#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include "myalloc.h"

/** Minimum region size, set to 1 GiB */
#define MIN_REGION_SIZE (1 << 30)

/** Multiple to which the block size must be rounded */
#define BLOCK_SIZE_MULTIPLE (8)

/** Bitmask for block_size in block header */
#define BLOCK_HEADER_BLOCK_SIZE (~7)
/** Bitmask for block_used in block header */
#define BLOCK_HEADER_BLOCK_USED (4)
/** Bitmask for previous_used in block header */
#define BLOCK_HEADER_PREVIOUS_USED (2)
/** Bitmask for last_block in block header */
#define BLOCK_HEADER_LAST_BLOCK (1)

/*** DATA STRUCTURES ***/

/**
 * @brief Header of a block
 * It is defined only as size_t to optimise its size. The last three bits of
 * the value are used for block_used, previous_used and last_block fields
 */
typedef size_t block_header;

/**
 * @brief Footer of a free block
 */
typedef struct {
	size_t block_size; /**< Size of this block, the same as in the header */
} block_footer;

/**
 * @brief Header of a region
 */
typedef struct {
	void *next_region; /**< Pointer to the next region in the list of regions */
	size_t region_size; /**< Size of this region in bytes, including this header */
	int used_blocks_num; /**< Number of used/allocated blocks in this region */
} region_header;

/*** FUNCTION PROTOTYPES ***/

/**
 * @brief Finds a free block of a suitable size
 * Finds a block that has content size (size of the block without the header)
 * equal to or larger than content_size. If not such block is found, a new
 * region is allocated
 * @param content_size Minimum content size of the block
 * @return Pointer to the header of the block
 */
void *get_free_block(size_t content_size);

/**
 * @brief Finds a free block of a suitable size in the region
 * Searches the specified region for a free block with a suitable block size
 * and returns the pointer to its header. If no matching block is found, NULL
 * is returned
 * @param region_ptr Pointer to the header of the region
 * @param block_size Minimum size of the free block
 * @return Pointer to the block header or NULL
 */
void *find_free_block_in_region(void *region_ptr, size_t block_size);

/**
 * @brief Determines whether a block is better than the currently best block
 * Used in the best-fit search algorithm. Compares sizes of the blocks to
 * determine if the first block is smaller.
 * @param block_ptr Pointer to the current block header
 * @param best_block_ptr Pointer to the best-so-far block header
 * @return Whether the block is better
 */
bool is_better_block(void *block_ptr, void *best_block_ptr);

/**
 * @brief Allocates the free block for the specified size
 * A free block is allocated, i.e. turned into a used block. The content size
 * of the new used block is specified. The free block might be split into a
 * used and free block if it is bigger than needed.
 * @param block_ptr Pointer of a free block header to be allocated
 * @param content_size Content size of the new block
 */
void allocate_block(void *block_ptr, size_t content_size);

/**
 * @brief Frees a used block
 * Turns a used block into a free block, possibly coalescing with neighbouring
 * free blocks. The pointer must be valid. If it is not, the behaviour is
 * undefined.
 * @param block_ptr Pointer to the content of the used block
 */
void free_block(void *block_ptr);

/**
 * @brief Writes a free block header and footer
 * Sets up the struct for a free block using the specified parameters.
 * @param ptr Pointer to the block header
 * @param size Block size
 * @param previous_used Whether the previos block is used
 * @param last_block Whether this is the last block
 */
void write_free_block(void *ptr, size_t size, bool previous_used,
	bool last_block);

/**
 * @brief Writes a used block header
 * Sets up the struct for a free block using the specified parameters.
 * @param ptr Pointer to the block header
 * @param size Block size
 * @param previous_used Whether the previos block is used
 * @param last_block Whether this is the last block
 */
void write_used_block(void *ptr, size_t size, bool previous_used,
	bool last_block);

/**
 * @brief Writes a block header
 * Sets up the block header struct using the specified parameters.
 * @param ptr Pointer to the block header
 * @param size Block size
 * @param block_used Whether the block is used
 * @param previous_used Whether the previos block is used
 * @param last_block Whether this is the last block
 */
void write_block_header(void *ptr, size_t size, bool block_used,
	bool previous_used, bool last_block);

/**
 * @brief Writes a block footer
 * Sets up the block footer struct using the specified parameters.
 * @param ptr Pointer to the block header
 * @param size Block size
 */
void write_block_footer(void *ptr, size_t size);

/**
 * @brief Updates the previous_used value of the block header
 * @param block_ptr Pointer to the block header
 * @param value Whether the previous block is used
 */
void set_previous_used(void *block_ptr, bool value);

/**
 * @brief Returns pointer to content of a block
 * Content of a block starts after the header struct.
 * @param block_ptr Pointer to the block header
 */
void *get_content_pointer(void *block_ptr);

/**
 * @brief Returns pointer to header of a block
 * Content of a block starts after the header struct.
 * @param block_ptr Pointer to the block content
 */
void *get_block_pointer(void *content_ptr);

/**
 * @brief Returns the size of the block
 * @param block_ptr Pointer to the block header
 */
size_t get_block_size(void *block_ptr);

/**
 * @brief Calculates block size based on content size
 * The block size will be rounded up to allow for block header size optimisation
 * @param content_size Content size of a block
 * @return Block size for the content size
 */
size_t get_block_size_from_content_size(size_t content_size);

/**
 * @brief Checks whether the block is used
 * @param block_ptr Pointer to the block header
 */
bool is_block_used(void *block_ptr);

/**
 * @brief Checks whether the previous block is used
 * If there is no previous block, it counts as if the previous block was used.
 * @param block_ptr Pointer to the block header
 */
bool is_previous_used(void* block_ptr);

/**
 * @brief Checks whether the next block is used
 * If there is no next block, it counts as if the next block was used.
 * @param block_ptr Pointer to the block header
 */
bool is_next_used(void *block_ptr);

/**
 * @brief Checks whether the block is the last one in its region
 * @param block_ptr Pointer to the block header
 */
bool is_last_block(void *block_ptr);

/**
 * @brief Returns pointer to the previous block
 * If there is no previous block, NULL is returned.
 * @param block_ptr Pointer to the block header
 * @return Pointer to the previous block header or NULL
 */
void *get_previous_block(void *block_ptr);

/**
 * @brief Returns pointer to the next block
 * If there is no next block, NULL is returned.
 * @param block_ptr Pointer to the block header
 * @return Pointer to the next block header or NULL
 */
void *get_next_block(void *block_ptr);

/**
 * @brief Allocates memory and sets up a new region
 * Allocates memory using mmap, sets up region header and creates a single
 * free block in the region. If the size of the block is too small, the region
 * is made bigger. The size of the region is rounded up to a multiple of a
 * memory page size. Returns NULL on failure.
 * @param block_size Minimum first block size
 * @return Pointer to the region header or NULL
 */
void *create_region(size_t block_size);

/**
 * @brief Releases memory used by the region
 * @param region_ptr Pointer to the region header
 */
void destroy_region(void *region_ptr);

/**
 * @brief Returns the address of the first block header in the region
 * @param region_ptr Pointer to the region header
 */
void *get_first_block(void *region_ptr);

/**
 * @brief Returns the address of the header of the next region
 * @param region_ptr Pointer to the region header
 * @return Pointer to the next region header or NULL
 */
void *get_next_region(void *region_ptr);

/**
 * @brief Updates the next_region field in the region header struct
 * @param region_ptr Pointer to the region header
 * @param next_region_ptr Pointer to the next region header
 */
void set_next_region(void *region_ptr, void *next_region_ptr);

/**
 * @brief Checks whether the block is in the specified region
 * @param block_ptr Pointer to the block header
 * @param region_ptr Pointer to the region header
 */
bool is_block_in_region(void *block_ptr, void *region_ptr);

/**
 * @brief Finds the region that contains the specified block
 * @param block_ptr Pointer to the block header
 * @return Pointer to the region header
 */
void *get_block_region(void *block_ptr);

/**
 * @brief Checks whether there are any used blocks in the region
 * @param region_ptr Pointer to the region header
 */
bool is_region_empty(void *region_ptr);

/**
 * @brief Updates the number of used blocks in the region
 * @param region_ptr Pointer to the region header
 * @param delta Number to add to the current value
 */
void update_region_used_blocks_num(void *region_ptr, int delta);

/**
 * @brief Rounds up the number to a multiple of the specified number
 * @param size Number to round up
 * @param multiple Multiple to round up to
 * @return Rounded number
 */
size_t round_up_size(size_t size, size_t multiple);

/*** GLOBAL VARIABLES ***/

/** @brief Pointer to the first region in the list */
static void *first_region_ptr = NULL;

/*** LIBRARY FUNCTIONS ***/

void *myalloc(int size) {
	void* free_block_ptr = get_free_block(size);

	if (free_block_ptr == NULL) {
		return NULL;
	}

	allocate_block(free_block_ptr, size);

	return get_content_pointer(free_block_ptr);
}

void myfree(void *ptr){
	free_block(ptr);
}

/*** SEARCH FUNCTIONS ***/

void *get_free_block(size_t content_size) {
	size_t block_size = get_block_size_from_content_size(content_size);

	void *region_ptr = first_region_ptr;
	/** @var Pointer to the last region in the list */
	void *last_region_ptr = NULL;
	/** @var Pointer to the best block in the best-fit algorithm */
	void *best_block_ptr = NULL;

	while (region_ptr != NULL) {
		last_region_ptr = region_ptr;

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
		// no suitable block found, need to create a new region

		void *free_region = create_region(block_size);

		if (free_region == NULL) {
			return NULL;
		}

		if (first_region_ptr == NULL) {
			// if this is the first region we need to update the global variable
			first_region_ptr = free_region;
		}

		if (last_region_ptr != NULL) {
			// update the next_region value of the last region in the list
			set_next_region(last_region_ptr, free_region);
		}

		return get_first_block(free_region);
	}
}

void *find_free_block_in_region(void *region_ptr, size_t block_size) {
	void *block_ptr = get_first_block(region_ptr);
	/** @var Pointer to the best block in the best-fit algorithm */
	void *best_block_ptr = NULL;

	do {
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

	return best_block_ptr;
}

bool is_better_block(void *block_ptr, void *best_block_ptr) {
	return best_block_ptr == NULL ||
		get_block_size(block_ptr) < get_block_size(best_block_ptr);
}

/*** ALLOCATION FUNCTIONS ***/

void allocate_block(void *block_ptr, size_t used_content_size) {
	size_t used_block_size = get_block_size_from_content_size(used_content_size);

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

	// after allocating a new block we need to update region's used block count
	void *region_ptr = get_block_region(block_ptr);
	update_region_used_blocks_num(region_ptr, 1);
}

/*** FREEING FUNCTIONS ***/

void free_block(void *content_ptr) {
	void *block_ptr = get_block_pointer(content_ptr);

	bool previous_used = is_previous_used(block_ptr);
	bool next_used = is_next_used(block_ptr);
	bool last_block = is_last_block(block_ptr);

	// params for the newly created free block
	// this might be a combination of several free blocks when coalescing
	void *new_block_ptr = block_ptr;
	size_t new_block_size = get_block_size(block_ptr);
	bool new_previous_used = previous_used;
	bool new_last_block = last_block;

	if (!previous_used) {
		// coalesce with the previous block
		void *previous_block = get_previous_block(block_ptr);

		new_block_ptr = previous_block;
		new_block_size += get_block_size(previous_block);
		new_previous_used = is_previous_used(previous_block);
	}

	if (!next_used) {
		// coalesce with the next block
		void *next_block = get_next_block(block_ptr);
		new_block_size += get_block_size(next_block);
		new_last_block = is_last_block(next_block);
	}

	write_free_block(new_block_ptr, new_block_size, new_previous_used, new_last_block);

	// update next block's previous_used value
	void *next_block = get_next_block(new_block_ptr);

	if (next_block != NULL) {
		set_previous_used(next_block, false);
	}

	// after freeing a block we need to update region's used block count
	void *region_ptr = get_block_region(block_ptr);
	update_region_used_blocks_num(region_ptr, -1);

	if (is_region_empty(region_ptr)) {
		// if the region contains no used blocks, it can be released
		destroy_region(region_ptr);
	}
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
		block_footer *previous_footer_ptr = block_ptr - sizeof(block_footer);
		return block_ptr - previous_footer_ptr->block_size;
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
		// requested block size is too small
		requested_block_size = MIN_REGION_SIZE;
	}

	// requested and actual region sizes may differ due to rounding up to page size
	size_t requested_region_size = requested_block_size + sizeof(region_header);
	size_t region_size = round_up_size(requested_region_size, getpagesize());

	void *region_ptr = mmap(0, region_size, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

	if (region_ptr == MAP_FAILED) {
		return NULL;
	}

	// set up region header
	region_header *header_ptr = region_ptr;
	header_ptr->next_region = NULL;
	header_ptr->region_size = region_size;
	header_ptr->used_blocks_num = 0;

	// set up the first block in the region
	void *block_ptr = get_first_block(region_ptr);
	size_t block_size = region_size - sizeof(region_header);
	write_free_block(block_ptr, block_size, true, true);

	return region_ptr;
}

void destroy_region(void *region_ptr) {
	region_header *header_ptr = region_ptr;

	// updating the linked list of regions
	if (region_ptr == first_region_ptr) {
		// special case when the removed region is the first in the list
		first_region_ptr = header_ptr->next_region;
	} else {
		// find the previous region header
		region_header *previous_header_ptr = first_region_ptr;

		while (previous_header_ptr->next_region != region_ptr) {
			previous_header_ptr = previous_header_ptr->next_region;
		}

		// remove the region from the list
		previous_header_ptr->next_region = header_ptr->next_region;
	}

	// release the memory to the OS
	munmap(region_ptr, header_ptr->region_size);
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
