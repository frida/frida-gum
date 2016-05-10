/*
 * Copyright (C) 2008-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum.h"

#include "gum-init.h"
#include "../libs/gum/heap/gumallocatorprobe-priv.h"
#include "guminterceptor-priv.h"
#include "gumlibc.h"
#include "gumprintf.h"
#include "gumtls-priv.h"

#include <capstone.h>
#include <glib-object.h>
#include <gio/gio.h>
#include <string.h>

static gpointer do_init (gpointer data);
static void gum_destructor_invoke (GumDestructorFunc destructor);

static void gum_capstone_deinit (void);
static gpointer gum_capstone_malloc (gsize size);
static gpointer gum_capstone_calloc (gsize count, gsize size);
static gpointer gum_capstone_realloc (gpointer mem, gsize size);
static void gum_capstone_free (gpointer mem);

static GSList * gum_destructors = NULL;

void
gum_init (void)
{
  static GOnce init_once = G_ONCE_INIT;
  g_once (&init_once, do_init, NULL);
}

void
gum_deinit (void)
{
  _gum_tls_deinit ();

  g_slist_foreach (gum_destructors, (GFunc) gum_destructor_invoke, NULL);
  g_slist_free (gum_destructors);
  gum_destructors = NULL;

  _gum_allocator_probe_deinit ();

  _gum_interceptor_deinit ();

  gum_capstone_deinit ();
}

static gpointer
do_init (gpointer data)
{
  cs_opt_mem gum_cs_mem_callbacks = {
    gum_capstone_malloc,
    gum_capstone_calloc,
    gum_capstone_realloc,
    gum_capstone_free,
    gum_vsnprintf
  };

  gum_memory_init ();

#if GLIB_CHECK_VERSION (2, 46, 0)
  glib_init ();
  gio_init ();
#endif

  cs_option (0, CS_OPT_MEM, GPOINTER_TO_SIZE (&gum_cs_mem_callbacks));

  _gum_tls_init ();
  _gum_interceptor_init ();
  _gum_tls_realize ();

  return NULL;
}

void
_gum_register_destructor (GumDestructorFunc destructor)
{
  gum_destructors = g_slist_prepend (gum_destructors,
      GUM_FUNCPTR_TO_POINTER (destructor));
}

static void
gum_destructor_invoke (GumDestructorFunc destructor)
{
  destructor ();
}

typedef struct _GumPool GumPool;
typedef struct _GumBlock GumBlock;

struct _GumPool
{
  gsize block_size;
  GumBlock * free;
  GumPool * next;
};

struct _GumBlock
{
  GumPool * pool;
  GumBlock * next;
};

#define GUM_ALIGNED_SIZE(s) ((s + (16 - 1)) & ~(16 -1))
#define GUM_POOL_HEADER_SIZE GUM_ALIGNED_SIZE (sizeof (GumPool))
#define GUM_BLOCK_HEADER_SIZE GUM_ALIGNED_SIZE (sizeof (GumBlock))

#define GUM_BLOCK_TO_DATA_POINTER(b) \
    ((gpointer) ((guint8 *) b + GUM_BLOCK_HEADER_SIZE))
#define GUM_BLOCK_FROM_DATA_POINTER(p) \
    ((GumBlock *) ((guint8 *) p - GUM_BLOCK_HEADER_SIZE))

static GumPool * pools;

static void
gum_capstone_deinit (void)
{
  while (pools != NULL)
  {
    GumPool * next;

    next = pools->next;
    gum_free_pages (pools);
    pools = next;
  }
}

static gpointer
gum_capstone_malloc (gsize size)
{
  guint page_size;

  page_size = gum_query_page_size ();

  do
  {
    GumPool * head, * pool;
    GumBlock * block, * next_block;
    gsize aligned_block_size, pool_size, pages;
    gpointer pool_start, pool_end;

    head = pools;
    pool = NULL;
    for (pool = pools; pool != NULL; pool = pool->next)
    {
      if (pool->block_size == size)
      {
        do
        {
          block = pool->free;
          if (block == NULL)
            break;
        }
        while (!g_atomic_pointer_compare_and_exchange (&pool->free, block,
            block->next));

        if (block != NULL)
          return GUM_BLOCK_TO_DATA_POINTER (block);
      }
    }

    aligned_block_size = GUM_BLOCK_HEADER_SIZE + GUM_ALIGNED_SIZE (size);
    pool_size = GUM_POOL_HEADER_SIZE + (100 * aligned_block_size);
    pages = pool_size / page_size;
    if (pool_size % page_size != 0)
      pages++;

    pool_start = gum_alloc_n_pages (pages, GUM_PAGE_RW);
    pool_end = (guint8 *) pool_start + pool_size;
    pool = (GumPool *) pool_start;
    pool->block_size = size;
    block = (GumBlock *) ((guint8 *) pool_start + GUM_POOL_HEADER_SIZE);
    pool->free = block;
    do
    {
      next_block = (GumBlock *) ((guint8 *) block + aligned_block_size);
      if (next_block == pool_end)
        next_block = NULL;
      block->pool = pool;
      block->next = next_block;
      block = next_block;
    }
    while (next_block != NULL);
    pool->next = head;
    if (!g_atomic_pointer_compare_and_exchange (&pools, head, pool))
      gum_free_pages (pool);
  }
  while (TRUE);
}

static gpointer
gum_capstone_calloc (gsize count,
                     gsize size)
{
  gpointer result;
  gsize total;

  total = count * size;
  result = gum_capstone_malloc (total);
  gum_memset (result, 0, total);

  return result;
}

static gpointer
gum_capstone_realloc (gpointer mem,
                      gsize size)
{
  GumBlock * block;
  gpointer result;

  if (mem == NULL)
    return gum_capstone_malloc (size);

  block = GUM_BLOCK_FROM_DATA_POINTER (mem);

  result = gum_capstone_malloc (size);
  memcpy (result, mem, MIN (block->pool->block_size, size));
  gum_capstone_free (mem);

  return result;
}

static void
gum_capstone_free (gpointer mem)
{
  GumBlock * block, * next;
  GumPool * pool;

  if (mem == NULL)
    return;

  block = GUM_BLOCK_FROM_DATA_POINTER (mem);
  pool = block->pool;
  do
  {
    next = pool->free;
    block->next = next;
  }
  while (!g_atomic_pointer_compare_and_exchange (&pool->free, next, block));
}
