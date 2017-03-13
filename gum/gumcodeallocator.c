/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcodeallocator.h"

#include "gumcloak.h"
#include "gumcodesegment.h"
#include "gummemory.h"
#include "gumprocess-priv.h"
#ifdef HAVE_ARM
# include "gumarmwriter.h"
# include "gumthumbwriter.h"
#endif
#ifdef HAVE_ARM64
# include "gumarm64writer.h"
#endif

#if defined (HAVE_ELF_H)
# include <elf.h>
#elif defined (HAVE_SYS_ELF_H)
# include <sys/elf.h>
#endif
#include <string.h>

#define GUM_CODE_SLICE_ELEMENT_FROM_SLICE(s) \
    ((GumCodeSliceElement *) (((guint8 *) (s)) - \
        G_STRUCT_OFFSET (GumCodeSliceElement, slice)))

#if GLIB_SIZEOF_VOID_P == 8
# define GUM_CODE_DEFLECTOR_CAVE_SIZE 24
#else
# define GUM_CODE_DEFLECTOR_CAVE_SIZE 8
#endif

typedef struct _GumCodePages GumCodePages;
typedef struct _GumCodeSliceElement GumCodeSliceElement;
typedef struct _GumCodeDeflectorDispatcher GumCodeDeflectorDispatcher;
typedef struct _GumCodeDeflectorImpl GumCodeDeflectorImpl;
typedef struct _GumProbeRangeForCodeCaveContext GumProbeRangeForCodeCaveContext;
typedef struct _GumInsertDeflectorContext GumInsertDeflectorContext;

typedef void (* GumModifyCaveFunc) (GumCodeDeflectorDispatcher * self,
    gpointer cave, gsize size, GumAddress pc, gpointer user_data);

struct _GumCodeSliceElement
{
  GList parent;
  GumCodeSlice slice;
};

struct _GumCodePages
{
  gint ref_count;

  GumCodeSegment * segment;
  gpointer data;
  gsize size;

  GumCodeAllocator * allocator;

  GumCodeSliceElement elements[1];
};

struct _GumCodeDeflectorDispatcher
{
  GSList * callers;

  gpointer address;
  gpointer trampoline;
  gpointer thunk;

  gpointer original_data;
  gsize original_size;
};

struct _GumCodeDeflectorImpl
{
  GumCodeDeflector parent;

  GumCodeAllocator * allocator;
};

struct _GumProbeRangeForCodeCaveContext
{
  const GumAddressSpec * caller;

  GumMemoryRange cave;
};

struct _GumInsertDeflectorContext
{
  gpointer return_address;
  gpointer dedicated_target;
};

static GumCodeSlice * gum_code_allocator_try_alloc_batch_near (
    GumCodeAllocator * self, const GumAddressSpec * spec);

static void gum_code_pages_unref (GumCodePages * self);

static gboolean gum_code_slice_is_near (const GumCodeSlice * self,
    const GumAddressSpec * spec);
static gboolean gum_code_slice_is_aligned (const GumCodeSlice * slice,
    gsize alignment);

static GumCodeDeflectorDispatcher * gum_code_deflector_dispatcher_new (
    const GumAddressSpec * caller, gpointer return_address,
    gpointer dedicated_target);
static void gum_code_deflector_dispatcher_free (
    GumCodeDeflectorDispatcher * dispatcher);
static void gum_insert_deflector (GumCodeDeflectorDispatcher * self,
    gpointer cave, gsize size, GumAddress pc, GumInsertDeflectorContext * ctx);
static void gum_remove_deflector (GumCodeDeflectorDispatcher * self,
    gpointer cave, gsize size, GumAddress pc, gpointer user_data);
static gpointer gum_code_deflector_dispatcher_lookup (
    GumCodeDeflectorDispatcher * self, gpointer return_address);
static void gum_code_deflector_dispatcher_modify_cave (
    GumCodeDeflectorDispatcher * self, GumModifyCaveFunc func,
    gpointer user_data);

static gboolean gum_probe_range_for_code_cave (const GumRangeDetails * details,
    gpointer user_data);

void
gum_code_allocator_init (GumCodeAllocator * allocator,
                         gsize slice_size)
{
  allocator->slice_size = slice_size;
  allocator->pages_per_batch = 7;
  allocator->slices_per_batch =
      (allocator->pages_per_batch * gum_query_page_size ()) / slice_size;
  allocator->pages_metadata_size = sizeof (GumCodePages) +
      ((allocator->slices_per_batch - 1) * sizeof (GumCodeSliceElement));

  allocator->uncommitted_pages = NULL;
  allocator->dirty_pages = g_hash_table_new (NULL, NULL);
  allocator->free_slices = NULL;

  allocator->dispatchers = NULL;
}

void
gum_code_allocator_free (GumCodeAllocator * allocator)
{
  g_slist_foreach (allocator->dispatchers,
      (GFunc) gum_code_deflector_dispatcher_free, NULL);
  g_slist_free (allocator->dispatchers);
  allocator->dispatchers = NULL;

  g_list_foreach (allocator->free_slices, (GFunc) gum_code_pages_unref, NULL);
  g_hash_table_unref (allocator->dirty_pages);
  g_slist_free (allocator->uncommitted_pages);
  allocator->uncommitted_pages = NULL;
  allocator->dirty_pages = NULL;
  allocator->free_slices = NULL;
}

GumCodeSlice *
gum_code_allocator_alloc_slice (GumCodeAllocator * self)
{
  return gum_code_allocator_try_alloc_slice_near (self, NULL, 0);
}

GumCodeSlice *
gum_code_allocator_try_alloc_slice_near (GumCodeAllocator * self,
                                         const GumAddressSpec * spec,
                                         gsize alignment)
{
  GList * cur;

  for (cur = self->free_slices; cur != NULL; cur = cur->next)
  {
    GumCodeSliceElement * element = (GumCodeSliceElement *) cur;
    GumCodeSlice * slice = &element->slice;

    if (gum_code_slice_is_near (slice, spec) &&
        gum_code_slice_is_aligned (slice, alignment))
    {
      GumCodePages * pages = element->parent.data;

      self->free_slices = g_list_remove_link (self->free_slices, cur);

      g_hash_table_insert (self->dirty_pages, pages, pages);

      return slice;
    }
  }

  return gum_code_allocator_try_alloc_batch_near (self, spec);
}

void
gum_code_allocator_commit (GumCodeAllocator * self)
{
  gboolean rwx_supported;
  GSList * cur;
  GumCodePages * pages;
  GHashTableIter iter;

  rwx_supported = gum_query_is_rwx_supported ();

  for (cur = self->uncommitted_pages; cur != NULL; cur = cur->next)
  {
    GumCodeSegment * segment;

    pages = cur->data;
    segment = pages->segment;

    if (segment != NULL)
    {
      gum_code_segment_realize (segment);
      gum_code_segment_map (segment, 0,
          gum_code_segment_get_virtual_size (segment),
          gum_code_segment_get_address (segment));
    }
    else
    {
      gum_mprotect (pages->data, pages->size, GUM_PAGE_RX);
    }
  }
  g_slist_free (self->uncommitted_pages);
  self->uncommitted_pages = NULL;

  g_hash_table_iter_init (&iter, self->dirty_pages);
  while (g_hash_table_iter_next (&iter, (gpointer *) &pages, NULL))
  {
    gum_clear_cache (pages->data, pages->size);
  }
  g_hash_table_remove_all (self->dirty_pages);

  if (!rwx_supported)
  {
    g_list_foreach (self->free_slices, (GFunc) gum_code_pages_unref, NULL);
    self->free_slices = NULL;
  }
}

static GumCodeSlice *
gum_code_allocator_try_alloc_batch_near (GumCodeAllocator * self,
                                         const GumAddressSpec * spec)
{
  GumCodeSlice * result = NULL;
  gboolean rwx_supported, code_segment_supported;
  gsize size_in_pages, size_in_bytes;
  GumCodeSegment * segment;
  gpointer data;
  GumMemoryRange range;
  GumCodePages * pages;
  guint i;

  rwx_supported = gum_query_is_rwx_supported ();
  code_segment_supported = gum_code_segment_is_supported ();

  size_in_pages = self->pages_per_batch;
  size_in_bytes = size_in_pages * gum_query_page_size ();

  if (rwx_supported || !code_segment_supported)
  {
    GumPageProtection protection;

    protection = rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW;

    segment = NULL;
    if (spec != NULL)
    {
      data = gum_try_alloc_n_pages_near (size_in_pages, protection, spec);
      if (data == NULL)
        return NULL;
    }
    else
    {
      data = gum_alloc_n_pages (size_in_pages, protection);
    }
  }
  else
  {
    segment = gum_code_segment_new (size_in_bytes, spec);
    if (segment == NULL)
      return NULL;
    data = gum_code_segment_get_address (segment);
  }

  range.base_address = GUM_ADDRESS (data);
  range.size = size_in_bytes;
  gum_cloak_add_range (&range);

  pages = g_slice_alloc (self->pages_metadata_size);
  pages->ref_count = self->slices_per_batch;

  pages->segment = segment;
  pages->data = data;
  pages->size = size_in_bytes;

  pages->allocator = self;

  for (i = self->slices_per_batch; i != 0; i--)
  {
    guint slice_index = i - 1;
    GumCodeSliceElement * element = &pages->elements[slice_index];
    GList * link;
    GumCodeSlice * slice;

    slice = &element->slice;
    slice->data = (guint8 *) data + (slice_index * self->slice_size);
    slice->size = self->slice_size;

    link = &element->parent;
    link->data = pages;
    link->prev = NULL;
    if (slice_index == 0)
    {
      link->next = NULL;
      result = slice;
    }
    else
    {
      if (self->free_slices != NULL)
        self->free_slices->prev = link;
      link->next = self->free_slices;
      self->free_slices = link;
    }
  }

  if (!rwx_supported)
    self->uncommitted_pages = g_slist_prepend (self->uncommitted_pages, pages);

  g_hash_table_insert (self->dirty_pages, pages, pages);

  return result;
}

static void
gum_code_pages_unref (GumCodePages * self)
{
  self->ref_count--;
  if (self->ref_count == 0)
  {
    if (self->segment != NULL)
    {
      gum_code_segment_free (self->segment);
    }
    else
    {
      GumMemoryRange range;

      gum_free_pages (self->data);

      range.base_address = GUM_ADDRESS (self->data);
      range.size = self->size;
      gum_cloak_remove_range (&range);
    }

    g_slice_free1 (self->allocator->pages_metadata_size, self);
  }
}

void
gum_code_slice_free (GumCodeSlice * slice)
{
  GumCodeSliceElement * element;
  GumCodePages * pages;

  if (slice == NULL)
    return;

  element = GUM_CODE_SLICE_ELEMENT_FROM_SLICE (slice);
  pages = element->parent.data;

  if (gum_query_is_rwx_supported ())
  {
    GumCodeAllocator * allocator = pages->allocator;
    GList * link = &element->parent;

    if (allocator->free_slices != NULL)
      allocator->free_slices->prev = link;
    link->next = allocator->free_slices;
    allocator->free_slices = link;
  }
  else
  {
    gum_code_pages_unref (pages);
  }
}

static gboolean
gum_code_slice_is_near (const GumCodeSlice * self,
                        const GumAddressSpec * spec)
{
  gssize near_address;
  gssize slice_start, slice_end;
  gsize distance_start, distance_end;

  if (spec == NULL)
    return TRUE;

  near_address = (gssize) spec->near_address;

  slice_start = (gssize) self->data;
  slice_end = slice_start + self->size - 1;

  distance_start = ABS (near_address - slice_start);
  distance_end = ABS (near_address - slice_end);

  return distance_start <= spec->max_distance &&
      distance_end <= spec->max_distance;
}

static gboolean
gum_code_slice_is_aligned (const GumCodeSlice * slice,
                           gsize alignment)
{
  if (alignment == 0)
    return TRUE;

  return GPOINTER_TO_SIZE (slice->data) % alignment == 0;
}

GumCodeDeflector *
gum_code_allocator_alloc_deflector (GumCodeAllocator * self,
                                    const GumAddressSpec * caller,
                                    gpointer return_address,
                                    gpointer target,
                                    gboolean dedicated)
{
  GumCodeDeflectorDispatcher * dispatcher = NULL;
  GSList * cur;
  GumCodeDeflectorImpl * impl;
  GumCodeDeflector * deflector;

  if (!dedicated)
  {
    for (cur = self->dispatchers; cur != NULL; cur = cur->next)
    {
      GumCodeDeflectorDispatcher * d = cur->data;
      gsize distance;

      distance = ABS ((gssize) d->address - (gssize) caller->near_address);
      if (distance <= caller->max_distance)
      {
        dispatcher = d;
        break;
      }
    }
  }

  if (dispatcher == NULL)
  {
    dispatcher = gum_code_deflector_dispatcher_new (caller, return_address,
        dedicated ? target : NULL);
    if (dispatcher == NULL)
      return NULL;
    self->dispatchers = g_slist_prepend (self->dispatchers, dispatcher);
  }

  impl = g_slice_new (GumCodeDeflectorImpl);

  deflector = &impl->parent;
  deflector->return_address = return_address;
  deflector->target = target;
  deflector->trampoline = dispatcher->trampoline;

  impl->allocator = self;

  dispatcher->callers = g_slist_prepend (dispatcher->callers, deflector);

  return deflector;
}

void
gum_code_deflector_free (GumCodeDeflector * deflector)
{
  GumCodeDeflectorImpl * impl = (GumCodeDeflectorImpl *) deflector;
  GumCodeAllocator * allocator;
  GSList * cur;

  if (deflector == NULL)
    return;

  allocator = impl->allocator;

  for (cur = allocator->dispatchers; cur != NULL; cur = cur->next)
  {
    GumCodeDeflectorDispatcher * dispatcher = cur->data;
    GSList * entry;

    entry = g_slist_find (dispatcher->callers, deflector);
    if (entry != NULL)
    {
      g_slice_free (GumCodeDeflectorImpl, impl);

      dispatcher->callers = g_slist_delete_link (dispatcher->callers, entry);
      if (dispatcher->callers == NULL)
      {
        gum_code_deflector_dispatcher_free (dispatcher);
        allocator->dispatchers = g_slist_remove (allocator->dispatchers,
            dispatcher);
      }

      return;
    }
  }

  g_assert_not_reached ();
}

static GumCodeDeflectorDispatcher *
gum_code_deflector_dispatcher_new (const GumAddressSpec * caller,
                                   gpointer return_address,
                                   gpointer dedicated_target)
{
#if defined (HAVE_LINUX) && defined (HAVE_ARM64)
  /* FIXME: need to find a larger cave */

  (void) caller;
  (void) return_address;
  (void) dedicated_target;

  (void) gum_insert_deflector;
  (void) gum_probe_range_for_code_cave;

  return NULL;
#else
  GumCodeDeflectorDispatcher * dispatcher;
  GumProbeRangeForCodeCaveContext probe_ctx;
  gsize size_in_pages, size_in_bytes;
  GumInsertDeflectorContext insert_ctx;

  probe_ctx.caller = caller;

  probe_ctx.cave.base_address = 0;
  probe_ctx.cave.size = 0;

  _gum_process_enumerate_ranges (GUM_PAGE_RX, gum_probe_range_for_code_cave,
      &probe_ctx);

  if (probe_ctx.cave.base_address == 0)
    return NULL;

  size_in_pages = 1;
  size_in_bytes = size_in_pages * gum_query_page_size ();

  dispatcher = g_slice_new (GumCodeDeflectorDispatcher);

  dispatcher->callers = NULL;

  dispatcher->address = GSIZE_TO_POINTER (probe_ctx.cave.base_address);
  dispatcher->trampoline = dispatcher->address;
  dispatcher->thunk = (dedicated_target == NULL)
      ? gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW)
      : NULL;

  if (dispatcher->thunk != NULL)
  {
    GumMemoryRange range;

    range.base_address = GUM_ADDRESS (dispatcher->thunk);
    range.size = size_in_bytes;
    gum_cloak_add_range (&range);
  }

  dispatcher->original_data = g_memdup (dispatcher->address,
      probe_ctx.cave.size);
  dispatcher->original_size = probe_ctx.cave.size;

  insert_ctx.return_address = return_address;
  insert_ctx.dedicated_target = dedicated_target;

  gum_code_deflector_dispatcher_modify_cave (dispatcher,
      (GumModifyCaveFunc) gum_insert_deflector, &insert_ctx);

  if (dispatcher->thunk != NULL)
  {
    gum_mprotect (dispatcher->thunk, size_in_bytes, GUM_PAGE_RX);
    gum_clear_cache (dispatcher->thunk, size_in_bytes);
  }

  return dispatcher;
#endif
}

static void
gum_code_deflector_dispatcher_free (GumCodeDeflectorDispatcher * dispatcher)
{
  gum_code_deflector_dispatcher_modify_cave (dispatcher, gum_remove_deflector,
      NULL);

  g_free (dispatcher->original_data);

  if (dispatcher->thunk != NULL)
  {
    GumMemoryRange range;

    gum_free_pages (dispatcher->thunk);

    range.base_address = GUM_ADDRESS (dispatcher->thunk);
    range.size = gum_query_page_size ();
    gum_cloak_remove_range (&range);
  }

  g_slist_foreach (dispatcher->callers, (GFunc) gum_code_deflector_free, NULL);
  g_slist_free (dispatcher->callers);

  g_slice_free (GumCodeDeflectorDispatcher, dispatcher);
}

static void
gum_insert_deflector (GumCodeDeflectorDispatcher * self,
                      gpointer cave,
                      gsize size,
                      GumAddress pc,
                      GumInsertDeflectorContext * ctx)
{
# if defined (HAVE_ARM)
  GumThumbWriter tw;

  if (ctx->dedicated_target != NULL)
  {
    gboolean owner_is_arm;

    owner_is_arm = (GPOINTER_TO_SIZE (ctx->return_address) & 1) == 0;
    if (owner_is_arm)
    {
      GumArmWriter aw;

      gum_arm_writer_init (&aw, cave);
      aw.pc = pc;
      gum_arm_writer_put_ldr_reg_address (&aw, ARM_REG_PC,
          GUM_ADDRESS (ctx->dedicated_target));
      gum_arm_writer_flush (&aw);
      g_assert_cmpuint (gum_arm_writer_offset (&aw), <=, size);
      gum_arm_writer_free (&aw);

      self->trampoline = self->address;

      return;
    }

    gum_thumb_writer_init (&tw, cave);
    tw.pc = pc;
    gum_thumb_writer_put_ldr_reg_address (&tw, ARM_REG_PC,
        GUM_ADDRESS (ctx->dedicated_target));
  }
  else
  {
    gum_thumb_writer_init (&tw, self->thunk);

    gum_thumb_writer_put_push_regs (&tw, 2, ARM_REG_R9, ARM_REG_R12);

    gum_thumb_writer_put_call_address_with_arguments (&tw,
        GUM_ADDRESS (gum_code_deflector_dispatcher_lookup), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (self),
        GUM_ARG_REGISTER, ARM_REG_LR);

    gum_thumb_writer_put_pop_regs (&tw, 2, ARM_REG_R9, ARM_REG_R12);

    gum_thumb_writer_put_bx_reg (&tw, ARM_REG_R0);
    gum_thumb_writer_flush (&tw);

    gum_thumb_writer_reset (&tw, cave);
    tw.pc = pc;
    gum_thumb_writer_put_ldr_reg_address (&tw, ARM_REG_PC,
        GUM_ADDRESS (self->thunk) + 1);
  }

  gum_thumb_writer_flush (&tw);
  g_assert_cmpuint (gum_thumb_writer_offset (&tw), <=, size);
  gum_thumb_writer_free (&tw);

  self->trampoline = self->address + 1;
# elif defined (HAVE_ARM64)
  GumArm64Writer aw;

  if (ctx->dedicated_target != NULL)
  {
    gum_arm64_writer_init (&aw, cave);
    aw.pc = pc;
    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X0, ARM64_REG_LR);
    gum_arm64_writer_put_ldr_reg_address (&aw, ARM64_REG_X0,
        GUM_ADDRESS (ctx->dedicated_target));
    gum_arm64_writer_put_br_reg (&aw, ARM64_REG_X0);
  }
  else
  {
    gum_arm64_writer_init (&aw, self->thunk);

    /* push {q0-q7} */
    gum_arm64_writer_put_instruction (&aw, 0xadbf1fe6);
    gum_arm64_writer_put_instruction (&aw, 0xadbf17e4);
    gum_arm64_writer_put_instruction (&aw, 0xadbf0fe2);
    gum_arm64_writer_put_instruction (&aw, 0xadbf07e0);

    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X17, ARM64_REG_X18);
    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X15, ARM64_REG_X16);
    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X13, ARM64_REG_X14);
    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X11, ARM64_REG_X12);
    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X9, ARM64_REG_X10);
    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X7, ARM64_REG_X8);
    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X5, ARM64_REG_X6);
    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X3, ARM64_REG_X4);
    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X1, ARM64_REG_X2);

    gum_arm64_writer_put_call_address_with_arguments (&aw,
        GUM_ADDRESS (gum_code_deflector_dispatcher_lookup), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (self),
        GUM_ARG_REGISTER, ARM64_REG_LR);

    gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X1, ARM64_REG_X2);
    gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X3, ARM64_REG_X4);
    gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X5, ARM64_REG_X6);
    gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X7, ARM64_REG_X8);
    gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X9, ARM64_REG_X10);
    gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X11, ARM64_REG_X12);
    gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X13, ARM64_REG_X14);
    gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X15, ARM64_REG_X16);
    gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X17, ARM64_REG_X18);

    /* pop {q0-q7} */
    gum_arm64_writer_put_instruction (&aw, 0xacc107e0);
    gum_arm64_writer_put_instruction (&aw, 0xacc10fe2);
    gum_arm64_writer_put_instruction (&aw, 0xacc117e4);
    gum_arm64_writer_put_instruction (&aw, 0xacc11fe6);

    gum_arm64_writer_put_br_reg (&aw, ARM64_REG_X0);
    gum_arm64_writer_flush (&aw);

    gum_arm64_writer_reset (&aw, cave);
    aw.pc = pc;
    gum_arm64_writer_put_ldr_reg_address (&aw, ARM64_REG_X0,
        GUM_ADDRESS (self->thunk));
    gum_arm64_writer_put_br_reg (&aw, ARM64_REG_X0);
  }

  gum_arm64_writer_flush (&aw);
  g_assert_cmpuint (gum_arm64_writer_offset (&aw), <=, size);
  gum_arm64_writer_free (&aw);

  self->trampoline = self->address;
# else
  (void) self;
  (void) cave;
  (void) size;
  (void) pc;
  (void) ctx;

  (void) gum_code_deflector_dispatcher_lookup;
# endif
}

static void
gum_remove_deflector (GumCodeDeflectorDispatcher * self,
                      gpointer cave,
                      gsize size,
                      GumAddress pc,
                      gpointer user_data)
{
  (void) size;
  (void) pc;
  (void) user_data;

  memcpy (cave, self->original_data, self->original_size);
}

static gpointer
gum_code_deflector_dispatcher_lookup (GumCodeDeflectorDispatcher * self,
                                      gpointer return_address)
{
  GSList * cur;

  for (cur = self->callers; cur != NULL; cur = cur->next)
  {
    GumCodeDeflector * caller = cur->data;

    if (caller->return_address == return_address)
      return caller->target;
  }

  return NULL;
}

static void
gum_code_deflector_dispatcher_modify_cave (GumCodeDeflectorDispatcher * self,
                                           GumModifyCaveFunc func,
                                           gpointer user_data)
{
  gsize page_size;
  gpointer page_start;
  gsize page_offset;
  gboolean rwx_supported, code_segment_supported;

  page_size = gum_query_page_size ();
  page_start =
      GSIZE_TO_POINTER (GPOINTER_TO_SIZE (self->address) & ~(page_size - 1));
  page_offset = GPOINTER_TO_SIZE (self->address) & (page_size - 1);

  rwx_supported = gum_query_is_rwx_supported ();
  code_segment_supported = gum_code_segment_is_supported ();

  if (rwx_supported || !code_segment_supported)
  {
    GumPageProtection protection;

    protection = rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW;

    gum_mprotect (page_start, page_size, protection);

    func (self, self->address, self->original_size, GUM_ADDRESS (self->address),
        user_data);

    gum_mprotect (page_start, page_size, GUM_PAGE_RX);
  }
  else
  {
    GumCodeSegment * segment;
    guint8 * scratch_page;

    segment = gum_code_segment_new (page_size, NULL);

    scratch_page = gum_code_segment_get_address (segment);
    memcpy (scratch_page, page_start, page_size);

    func (self, scratch_page + page_offset, self->original_size,
        GUM_ADDRESS (self->address), user_data);

    gum_code_segment_realize (segment);
    gum_code_segment_map (segment, 0, page_size, page_start);
    gum_code_segment_free (segment);
  }

  gum_clear_cache (self->address, self->original_size);
}

static gboolean
gum_probe_range_for_code_cave (const GumRangeDetails * details,
                               gpointer user_data)
{
#if defined (HAVE_DARWIN) || defined (HAVE_LINUX)
  const GumMemoryRange * range = details->range;
  GumProbeRangeForCodeCaveContext * ctx = user_data;
  const GumAddressSpec * caller = ctx->caller;
  gsize distance_from_start, distance_from_end;
  GumAddress header_address;

  distance_from_start = ABS ((gssize) range->base_address -
      (gssize) caller->near_address);
  distance_from_end = ABS ((gssize) (range->base_address + range->size) -
      (gssize) caller->near_address);
  if (distance_from_start > caller->max_distance &&
      distance_from_end > caller->max_distance)
    return TRUE;

  for (header_address = range->base_address;
      header_address < range->base_address + range->size;
      header_address += 4096)
  {
    GumAddress cave_address;
    gsize distance;
    const gchar * magic;
    gsize magic_size;
    const guint8 empty_cave[GUM_CODE_DEFLECTOR_CAVE_SIZE] = { 0, };

# if defined (HAVE_DARWIN)
    cave_address = header_address + 4096 - sizeof (empty_cave);
#  if GLIB_SIZEOF_VOID_P == 8
    magic = "\xcf\xfa\xed\xfe";
#  else
    magic = "\xce\xfa\xed\xfe";
#  endif
    magic_size = 4;
# elif defined (HAVE_LINUX)
    cave_address = header_address + 8;
    magic = ELFMAG;
    magic_size = SELFMAG;
# endif

    distance = ABS ((gssize) cave_address - (gssize) caller->near_address);
    if (distance > caller->max_distance)
      continue;

    if (memcmp (GSIZE_TO_POINTER (header_address), magic, magic_size) != 0)
      continue;

    if (memcmp (GSIZE_TO_POINTER (cave_address), empty_cave,
        sizeof (empty_cave)) != 0)
    {
# if defined (HAVE_DARWIN)
      gboolean found_empty_cave, nothing_in_front_of_cave;

      found_empty_cave = FALSE;
      nothing_in_front_of_cave = TRUE;

      do
      {
        cave_address -= sizeof (empty_cave);

        found_empty_cave = memcmp (GSIZE_TO_POINTER (cave_address), empty_cave,
            sizeof (empty_cave)) == 0;
      }
      while (!found_empty_cave && cave_address > header_address + 0x500);

      if (found_empty_cave)
      {
        gsize offset;

        for (offset = sizeof (empty_cave);
            offset <= 2 * sizeof (empty_cave);
            offset += sizeof (empty_cave))
        {
          nothing_in_front_of_cave = memcmp (
              GSIZE_TO_POINTER (cave_address - offset), empty_cave,
              sizeof (empty_cave)) == 0;
        }
      }

      if (!(found_empty_cave && nothing_in_front_of_cave))
        continue;
# elif defined (HAVE_LINUX)
      continue;
#endif
    }

    ctx->cave.base_address = cave_address;
    ctx->cave.size = sizeof (empty_cave);
    return FALSE;
  }

  return TRUE;
#else
  (void) details;
  (void) user_data;

  return FALSE;
#endif
}
