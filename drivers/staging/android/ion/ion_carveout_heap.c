/*
 * drivers/staging/android/ion/ion_carveout_heap.c
 *
 * Copyright (C) 2011 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/spinlock.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/genalloc.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "ion.h"
#include "ion_priv.h"

#define ION_CARVEOUT_ALLOCATE_FAIL	-1

struct ion_carveout_heap {
	struct ion_heap heap;
	struct gen_pool *pool;
	ion_phys_addr_t base;
};

static ion_phys_addr_t ion_carveout_allocate(struct ion_heap *heap,
					     unsigned long size,
					     unsigned long align)
{
	struct ion_carveout_heap *carveout_heap =
		container_of(heap, struct ion_carveout_heap, heap);
	unsigned long offset = gen_pool_alloc(carveout_heap->pool, size);

	if (!offset)
		return ION_CARVEOUT_ALLOCATE_FAIL;

	return offset;
}

static void ion_carveout_free(struct ion_heap *heap, ion_phys_addr_t addr,
			      unsigned long size)
{
	struct ion_carveout_heap *carveout_heap =
		container_of(heap, struct ion_carveout_heap, heap);

	if (addr == ION_CARVEOUT_ALLOCATE_FAIL)
		return;
	gen_pool_free(carveout_heap->pool, addr, size);
}

static int ion_carveout_heap_allocate(struct ion_heap *heap,
				      struct ion_buffer *buffer,
				      unsigned long size, unsigned long align,
				      unsigned long flags)
{
	struct sg_table *table;
	ion_phys_addr_t paddr;
	int ret;

	if (align > PAGE_SIZE)
		return -EINVAL;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table) {
		printk("In %s line %d: kmalloc fail!\n", __func__, __LINE__);
		return -ENOMEM;
	}
	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret) {
		printk("In %s line %d: sg_alloc_table fail!\n",
			   __func__, __LINE__);
		goto err_free;
	}

	paddr = ion_carveout_allocate(heap, size, align);
	if (paddr == ION_CARVEOUT_ALLOCATE_FAIL) {
		ret = -ENOMEM;
		printk("\nIn %s line %d: alloc buffer size: %lu Byte fail!\n",
			   __func__, __LINE__, size);
		goto err_free_table;
	}

	sg_set_page(table->sgl, pfn_to_page(PFN_DOWN(paddr)), size, 0);
	buffer->sg_table = table;

	return 0;

err_free_table:
	sg_free_table(table);
err_free:
	kfree(table);
	return ret;
}

static void ion_carveout_heap_free(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct sg_table *table = buffer->sg_table;
	struct page *page = sg_page(table->sgl);
	ion_phys_addr_t paddr = PFN_PHYS(page_to_pfn(page));

	ion_heap_buffer_zero(buffer);

	if (ion_buffer_cached(buffer))
		dma_sync_sg_for_device(get_ion_dev(), table->sgl, table->nents,
				       DMA_BIDIRECTIONAL);

	ion_carveout_free(heap, paddr, buffer->size);
	sg_free_table(table);
	kfree(table);
}


static int ion_carveout_heap_phys(struct ion_heap *heap,
				      struct ion_buffer *buffer,
				      ion_phys_addr_t *addr, size_t *len)
{
	struct sg_table *table = buffer->sg_table;
	struct page *page = sg_page(table->sgl);
	ion_phys_addr_t paddr = PFN_PHYS(page_to_pfn(page));

	*addr = paddr;
	*len = buffer->size;

	return 0;
}

static struct ion_heap_ops carveout_heap_ops = {
	.allocate = ion_carveout_heap_allocate,
	.free = ion_carveout_heap_free,
	.map_user = ion_heap_map_user,
	.map_kernel = ion_heap_map_kernel,
	.unmap_kernel = ion_heap_unmap_kernel,
	.phys = ion_carveout_heap_phys,
};

static int ion_carveout_debug_show(struct ion_heap *heap,
			struct seq_file *s, void *para)
{
	struct gen_pool *pool = NULL;
	struct gen_pool_chunk *chunk;
	int size, total_bits, bits_per_unit;
	int i, index, offset, tmp, busy;
	int busy_cnt = 0, free_cnt = 0, total_cnt;
	unsigned int dump_unit = SZ_64K;

	struct ion_carveout_heap *carveout_heap =
		container_of(heap, struct ion_carveout_heap, heap);

	pool = carveout_heap->pool;

	rcu_read_lock();
	list_for_each_entry_rcu(chunk, &pool->chunks, next_chunk) {
		size = chunk->end_addr - chunk->start_addr;
		total_bits = size >> pool->min_alloc_order;
		bits_per_unit = dump_unit >> pool->min_alloc_order;
		seq_printf(s, " Carveout memory layout(+: free, -: busy, unit: %dKB):\n",
			dump_unit / 1024);
		total_cnt = (chunk->end_addr + 1 - chunk->start_addr) / dump_unit;
		busy_cnt = 0;
		free_cnt = 0;
		for (i = 0, tmp = 0, busy = 0; i < total_bits; i++) {
			index = i >> 5;
			offset = i & 31;
			if (!busy && (chunk->bits[index] & (1<<offset)))
				busy = 1;
			if (++tmp == bits_per_unit) {
				busy ? (seq_printf(s, "-"), busy_cnt++) : (seq_printf(s, "+"), free_cnt);
				busy = 0;
				tmp = 0;
			}
		}

		free_cnt = total_cnt - busy_cnt;
		seq_printf(s, "\n Carveout area start:0x%lx end:0x%lx\n",
			chunk->start_addr, chunk->end_addr + 1);
		seq_printf(s, " Carveout area Total:%uMB Free:%uKB ~= %uMB\n",
			total_cnt * dump_unit / (1024 * 1024),
			free_cnt * dump_unit / 1024,
			free_cnt * dump_unit / (1024 * 1024));
	}
	rcu_read_unlock();

	return 0;

}
struct ion_heap *ion_carveout_heap_create(struct ion_platform_heap *heap_data)
{
	struct ion_carveout_heap *carveout_heap;
	int ret;

	struct page *page;
	size_t size;

	page = pfn_to_page(PFN_DOWN(heap_data->base));
	size = heap_data->size;

	ion_pages_sync_for_device(NULL, page, size, DMA_BIDIRECTIONAL);

	ret = ion_heap_pages_zero(page, size, pgprot_writecombine(PAGE_KERNEL));
	if (ret)
		return ERR_PTR(ret);

	carveout_heap = kzalloc(sizeof(*carveout_heap), GFP_KERNEL);
	if (!carveout_heap)
		return ERR_PTR(-ENOMEM);

	carveout_heap->pool = gen_pool_create(PAGE_SHIFT, -1);
	if (!carveout_heap->pool) {
		kfree(carveout_heap);
		return ERR_PTR(-ENOMEM);
	}
	carveout_heap->base = heap_data->base;
	gen_pool_add(carveout_heap->pool, carveout_heap->base, heap_data->size,
		     -1);
	carveout_heap->heap.ops = &carveout_heap_ops;
	carveout_heap->heap.type = ION_HEAP_TYPE_CARVEOUT;
	carveout_heap->heap.flags = ION_HEAP_FLAG_DEFER_FREE;
	carveout_heap->heap.debug_show = ion_carveout_debug_show;

	return &carveout_heap->heap;
}

void ion_carveout_heap_destroy(struct ion_heap *heap)
{
	struct ion_carveout_heap *carveout_heap =
	     container_of(heap, struct  ion_carveout_heap, heap);

	gen_pool_destroy(carveout_heap->pool);
	kfree(carveout_heap);
	carveout_heap = NULL;
}
