// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define ALIGNMENT 8 // must be a power of 2
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define SIZE_T_SIZE (ALIGN(sizeof(size_t))) // header size
#define MMAP_THRESHOLD (1024*128)
#define STATUS_FREE   0
#define STATUS_ALLOC  1
#define STATUS_MAPPED 2

int first;

struct block_meta *heap_start;

int verificare_malloc_calloc;

void coalesce_block(struct block_meta *heap_start)
{
	struct block_meta *local1, *local2;

	local1 = heap_start;

	local2 = heap_start->next;

	while (local2 != NULL) {
		if (local1->status == STATUS_FREE && local2->status == STATUS_FREE) {
			local1->size = local1->size + local2->size + sizeof(struct block_meta);
			local1->next = local2->next;
			if (local2->next != NULL)
				local2->next->prev = local1;
			local2 = local2->next;
		} else {
			local1 = local2;
			local2 = local1->next;
		}
	}
}

struct block_meta *find_best_fit_block(size_t size, struct block_meta *heap_start)
{
	struct block_meta *local1;

	struct block_meta *best_fit_block = NULL;

	int indice = 0;

	local1 = heap_start;

	while (local1->next != NULL) {
		if (local1->status == STATUS_FREE)
			if (local1->size >= size && (best_fit_block == NULL || ALIGN(local1->size) < best_fit_block->size)) {
				best_fit_block = local1;
				indice = 1;
			}
		local1 = local1->next;
	}

	if (local1->status == STATUS_FREE) {
		if (local1->size >= size && (best_fit_block == NULL || ALIGN(local1->size) < best_fit_block->size)) {
			indice = 1;
			best_fit_block = local1;
		}
		if (indice == 0) {
			best_fit_block = local1;
			sbrk(ALIGN(size - ALIGN(local1->size)));
			local1->size = ALIGN(size);
			local1->status = STATUS_ALLOC;
			return (void *)local1 + sizeof(struct block_meta);
		}
	}

	if (best_fit_block != NULL && best_fit_block->status == STATUS_FREE) {
		if (best_fit_block->size >= (sizeof(struct block_meta) + 8 + ALIGN(size))) {

			struct block_meta *free_block;

			free_block = (struct block_meta *)(ALIGN((size_t)best_fit_block + ALIGN(size + sizeof(struct block_meta))));
			free_block->size = ALIGN(best_fit_block->size - sizeof(struct block_meta) - ALIGN(size));
			free_block->next = best_fit_block->next;
			free_block->status = STATUS_FREE;
			free_block->prev = best_fit_block;
			best_fit_block->next = free_block;
			best_fit_block->status = STATUS_ALLOC;
			best_fit_block->size = ALIGN(size);
			return (void *)best_fit_block + sizeof(struct block_meta);
		}
		best_fit_block->status = STATUS_ALLOC;
		return (void *)best_fit_block + sizeof(struct block_meta);

	} else {
		struct block_meta *block;

		block = (struct block_meta *)sbrk(ALIGN((size) + sizeof(struct block_meta)));

		block->size = ALIGN(size);
		block->next = NULL;
		block->prev = local1;
		block->status = STATUS_ALLOC;
		local1->next = block;
		return (void *)block + sizeof(struct block_meta);
	}
}

void *os_malloc(size_t size)
{
	struct block_meta *block;
	size_t aux;

	if (size == 0)
		return NULL;

	if (verificare_malloc_calloc == 1)
		aux = 4096 - ALIGN(sizeof(struct block_meta));
	else
		aux = MMAP_THRESHOLD;

	if (first == 0 && size < aux) {
		heap_start = (struct block_meta *)sbrk(0);
		sbrk(MMAP_THRESHOLD);
		first = 1;
		heap_start->size = ALIGN(size);
		heap_start->next = NULL;
		heap_start->prev = NULL;
		heap_start->status = STATUS_ALLOC;
		return (void *)(heap_start + 1);
	}

	if (size < aux) {
		coalesce_block(heap_start);
		return (struct block_meta *)find_best_fit_block(size, heap_start);
	}

	size_t size1;

	size1 = ALIGN(size + sizeof(struct block_meta));

	block = mmap(NULL, size1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (block == MAP_FAILED)
		return NULL;
	block->size = ALIGN(size);
	block->prev = NULL;
	block->next = NULL;
	block->status = STATUS_MAPPED;
	return (void *)(block + 1);

	return NULL;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *block = (struct block_meta *)((char *)ptr - sizeof(struct block_meta));

	if (block) {
		if (block->status == STATUS_MAPPED) {
			munmap(block, block->size + sizeof(struct block_meta));
		} else if (block->status == STATUS_ALLOC) {
			block->status = STATUS_FREE;
			coalesce_block(heap_start);
		} else if (block->status == STATUS_FREE) {
			return;
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	verificare_malloc_calloc = 1;

	void *block_aux;

	block_aux = os_malloc(nmemb * size);

	if (block_aux == NULL)
		return NULL;

	memset(block_aux, 0, nmemb * size);

	return block_aux;

	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL && size != 0)
		return os_malloc(ALIGN(size));

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	if (ptr != NULL) {

		struct block_meta *data = (struct block_meta *)(ptr - sizeof(struct block_meta));

		if (data->status == STATUS_FREE)
			return NULL;
	}

	struct block_meta *header = (struct block_meta *)((char *)ptr - SIZE_T_SIZE);

	size_t oldsize = ALIGN(header->size + SIZE_T_SIZE);

	size_t newsize = ALIGN(size + SIZE_T_SIZE);

	void *newptr;

	if (oldsize >= newsize)
		return ptr;

	newptr = os_malloc(ALIGN(size));

	if (header->size < MMAP_THRESHOLD)
		memcpy(newptr, ptr, oldsize);
	else
		memcpy(newptr, ptr, size);
	os_free(ptr);
	return newptr;
}
