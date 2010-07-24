/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumtracer.h"

#include "gumcodereader.h"
#include "gumcodewriter.h"
#include "gummemory.h"
#include "gumrelocator.h"

#include <string.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* NOTE: buffer size must be a power of two! */
#define GUM_TRACER_BUFFER_SIZE          (32768)
#define GUM_TRACE_ENTRY_SIZE_IN_POT     (5)
#define GUM_TRACER_STACK_SIZE_IN_PAGES  (1)

#define GUM_MAX_FRAGMENT_SIZE           (16)

#define ENTER_MAX_SIZE                  (512)
#define LEAVE_MAX_SIZE                  (160)
#define REDIRECT_SIZE                   (5)
#define TIB_OFFSET_CUR_THREAD_ID        (0x24)
#define TIB_OFFSET_STACK                (0x700 + 12)
#define TIB_OFFSET_DEPTH                (0x700 + 16)

#define GT_ENTRY_OFFSET(M)              (G_STRUCT_OFFSET (GumTraceEntry, entry.header.M))

#define GUM_CODE_ALIGNMENT              (16)
#define GUM_ALIGN(N, A)                 (((N) + ((A) - 1)) & ~((A) - 1))

#define GUM_TRACER_SIZE_TO_BLOCKS(S) \
    ((S) / sizeof (GumTraceEntry)) + ((S) % sizeof (GumTraceEntry) != 0)

G_DEFINE_TYPE (GumTracer, gum_tracer, G_TYPE_OBJECT)

typedef struct _GumTracerFunction   GumTracerFunction;
typedef struct _GumRingBuffer       GumRingBuffer;
typedef struct _GumPatchedFragment  GumPatchedFragment;
typedef struct _GumCodePage         GumCodePage;
typedef enum _GumTrampolineKind     GumTrampolineKind;

struct _GumTracerPrivate
{
  guint page_size;
  gpointer get_time_impl;

  GPtrArray * names;
  GHashTable * address_to_name;
  GPtrArray * patched_fragments;
  GArray * code_pages;
  GumCodePage * last_alloc_cp;
  gpointer last_alloc_address;
  guint last_alloc_size;

  guint8 * stacks[GUM_MAX_THREADS];
  guint8 ** next_stack;

  GumRingBuffer * ringbuf;
};

struct _GumTracerFunction
{
  GumFunctionDetails details;
  guint name_id;
  guint disp_size;
};

struct _GumRingBuffer
{
  GumTraceEntry entries[GUM_TRACER_BUFFER_SIZE];

  volatile gint readpos;
  volatile gint writepos;
};

struct _GumPatchedFragment
{
  gpointer address;
  guint8 orig_bytes[GUM_MAX_FRAGMENT_SIZE];
  guint orig_len;
};

struct _GumCodePage
{
  guint8 * data;
  guint offset;
};

enum _GumTrampolineKind
{
  GUM_TRAMPOLINE_ENTER,
  GUM_TRAMPOLINE_LEAVE
};

#define GUM_TRACER_GET_PRIVATE(o) ((o)->priv)

static void gum_tracer_finalize (GObject * object);

static gboolean gum_tracer_knows_function_at (GumTracer * self,
    gpointer address);

static void gum_tracer_register_patched_fragment (GumTracer * self,
    gpointer address, guint size);
static void gum_patched_fragment_revert_and_free (GumPatchedFragment * frag);

static guint8 * gum_tracer_create_enter_trampoline (GumTracer * self,
    GumTracerFunction * func, gpointer leave_trampoline);
static guint8 * gum_tracer_create_leave_trampoline (GumTracer * self,
    GumTracerFunction * func);
static void gum_tracer_write_logging_code (GumTracer * self,
    GumTracerFunction * func, GumTrampolineKind kind, GumCodeWriter * cw);
static void gum_tracer_write_conversion_from_xax_index_to_address (
    GumTracer * self, GumCodeWriter * cw);

static gpointer gum_tracer_resolve (GumTracer * self, gpointer address);

static void gum_tracer_create_stacks (GumTracer * self);
static void gum_tracer_free_stacks (GumTracer * self);

static guint8 * gum_tracer_alloc_code (GumTracer * self, guint size);
static void gum_tracer_shrink_code (GumTracer * self, gpointer address, guint new_size);
static void gum_tracer_free_code_pages (GumTracer * self);

static void
gum_tracer_class_init (GumTracerClass * klass)
{
  GObjectClass * gobject_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumTracerPrivate));

  gobject_class->finalize = gum_tracer_finalize;
}

static void
gum_tracer_init (GumTracer * self)
{
  GumTracerPrivate * priv;
  HMODULE kmod;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_TRACER, GumTracerPrivate);
  priv = GUM_TRACER_GET_PRIVATE (self);

  priv->page_size = gum_query_page_size ();
  kmod = GetModuleHandleA ("kernel32.dll");
  priv->get_time_impl = GetProcAddress (kmod, "GetTickCount");

  priv->names = g_ptr_array_new ();
  priv->address_to_name = g_hash_table_new (NULL, NULL);
  priv->patched_fragments = g_ptr_array_new ();
  priv->code_pages = g_array_new (FALSE, FALSE, sizeof (GumCodePage));

  gum_tracer_create_stacks (self);

  priv->ringbuf = g_new0 (GumRingBuffer, 1);

  g_assert_cmpuint (sizeof (GumTraceEntry), ==,
      1 << GUM_TRACE_ENTRY_SIZE_IN_POT);
}

static void
gum_tracer_finalize (GObject * object)
{
  GumTracer * self = GUM_TRACER (object);
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);

  g_ptr_array_foreach (priv->patched_fragments,
      (GFunc) gum_patched_fragment_revert_and_free, NULL);
  g_ptr_array_free (priv->patched_fragments, TRUE);
  g_hash_table_unref (priv->address_to_name);
  g_ptr_array_foreach (priv->names, (GFunc) g_free, NULL);
  g_ptr_array_free (priv->names, TRUE);
  gum_tracer_free_code_pages (self);

  gum_tracer_free_stacks (self);

  g_free (priv->ringbuf);

  G_OBJECT_CLASS (gum_tracer_parent_class)->finalize (object);
}

GumTracer *
gum_tracer_new (void)
{
  return GUM_TRACER (g_object_new (GUM_TYPE_TRACER, NULL));
}

gboolean
gum_tracer_add_function (GumTracer * self,
                         const gchar * name,
                         gpointer address)
{
  GumFunctionDetails details;

  details.name = name;
  details.address = address;
  details.arglist_size = -1;

  return gum_tracer_add_function_with (self, &details);
}

gboolean
gum_tracer_add_function_with (GumTracer * self,
                              GumFunctionDetails * details)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);
  GumTracerFunction func;
  gchar * name_copy;
  guint8 * enter_trampoline, * leave_trampoline;
  GumCodeWriter cw;
  guint i;

  g_assert_cmpint (details->arglist_size, <, 128);
  g_assert (details->arglist_size == -1 || details->arglist_size % 4 == 0);

  func.details = *details;

  func.details.address = gum_tracer_resolve (self, func.details.address);
  if (func.details.address == NULL)
    return FALSE;

  if (!gum_relocator_can_relocate (func.details.address, REDIRECT_SIZE))
    return FALSE;

  func.name_id = priv->names->len;
  name_copy = g_strdup (details->name);
  g_ptr_array_add (priv->names, name_copy);
  g_hash_table_insert (priv->address_to_name, func.details.address, name_copy);

  leave_trampoline = gum_tracer_create_leave_trampoline (self, &func);
  enter_trampoline = gum_tracer_create_enter_trampoline (self, &func,
      leave_trampoline);

  gum_tracer_register_patched_fragment (self, func.details.address,
      func.disp_size);

  gum_mprotect (func.details.address, REDIRECT_SIZE, GUM_PAGE_RWX);
  gum_code_writer_init (&cw, func.details.address);
  gum_code_writer_put_jmp (&cw, enter_trampoline);
  for (i = 0; i < func.disp_size - REDIRECT_SIZE; i++)
    gum_code_writer_put_int3 (&cw);
  gum_code_writer_free (&cw);

  return TRUE;
}

static gboolean
gum_tracer_knows_function_at (GumTracer * self,
                              gpointer address)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);

  return g_hash_table_lookup (priv->address_to_name, address) != NULL;
}

const gchar *
gum_tracer_name_id_to_string (GumTracer * self, guint id)
{
  return g_ptr_array_index (self->priv->names, id);
}

GumTraceEntry *
gum_tracer_drain (GumTracer * self,
                  guint * num_entries)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);
  GumRingBuffer * rb = priv->ringbuf;
  GumTraceEntry * entries = NULL;
  guint count, i;
  gint startpos;
  guint arglist_blocks_left;

  count = MIN (rb->writepos - rb->readpos, GUM_TRACER_BUFFER_SIZE);
  if (count == 0)
    goto no_entries;

  entries = g_new (GumTraceEntry, count);
  startpos = rb->readpos;
  arglist_blocks_left = 0;

  for (i = 0; i < count; i++)
  {
    GumTraceEntry * entry =
        &rb->entries[(startpos + i) % GUM_TRACER_BUFFER_SIZE];

    if (arglist_blocks_left == 0)
    {
      if (G_UNLIKELY (GUM_TRACE_ENTRY_TYPE (entry) == GUM_ENTRY_INVALID))
      {
        count = i;

        if (G_LIKELY (i > 0))
          break;
        else
          goto no_entries;
      }

      if (GUM_TRACE_ENTRY_ARGLIST_SIZE (entry) != 0)
      {
        arglist_blocks_left =
            GUM_TRACER_SIZE_TO_BLOCKS (GUM_TRACE_ENTRY_ARGLIST_SIZE (entry));
      }
    }
    else
    {
      arglist_blocks_left--;
    }

    entries[i] = *entry;
    GUM_TRACE_ENTRY_TYPE (entry) = GUM_ENTRY_INVALID;
  }

  rb->readpos += count;

  *num_entries = count;
  return entries;

no_entries:
  *num_entries = 0;
  g_free (entries);
  return NULL;
}

static void
gum_tracer_register_patched_fragment (GumTracer * self,
                                      gpointer address,
                                      guint size)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);
  GumPatchedFragment * frag;

  g_assert (size <= sizeof (frag->orig_bytes));

  frag = g_slice_new (GumPatchedFragment);
  frag->address = address;
  memcpy (frag->orig_bytes, address, size);
  frag->orig_len = size;

  g_ptr_array_add (priv->patched_fragments, frag);
}

static gboolean
gum_tracer_has_patched_address (GumTracer * self)
{
  return FALSE;
}

static void
gum_patched_fragment_revert_and_free (GumPatchedFragment * frag)
{
  memcpy (frag->address, frag->orig_bytes, frag->orig_len);

  g_slice_free (GumPatchedFragment, frag);
}

static guint8 *
gum_tracer_create_enter_trampoline (GumTracer * self,
                                    GumTracerFunction * func,
                                    gpointer leave_trampoline)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);
  const gchar * setup_stack_lbl = "setup_stack";
  const gchar * stack_acq_lbl = "stack_acquired";
  guint8 * code;
  GumCodeWriter cw;
  GumRelocator rl;
  guint reloc_size;

  code = gum_tracer_alloc_code (self, ENTER_MAX_SIZE);
  gum_code_writer_init (&cw, code);

  /* FIXME: we clobber ecx which is used for C++ methods */

  /* first, logging */
  gum_tracer_write_logging_code (self, func, GUM_TRAMPOLINE_ENTER, &cw);

  /* get hold of our stack */
  gum_code_writer_put_mov_reg_fs_u32_ptr (&cw, GUM_REG_XAX, TIB_OFFSET_STACK);
  gum_code_writer_put_test_reg_reg (&cw, GUM_REG_XAX, GUM_REG_XAX);
  gum_code_writer_put_jz_label (&cw, setup_stack_lbl, GUM_UNLIKELY);

  /* push return address onto our stack  */
  gum_code_writer_put_label (&cw, stack_acq_lbl);
  gum_code_writer_put_mov_reg_reg_ptr (&cw, GUM_REG_XCX, GUM_REG_XSP);
  gum_code_writer_put_mov_reg_ptr_reg (&cw, GUM_REG_XAX, GUM_REG_XCX);
  gum_code_writer_put_add_reg_imm (&cw, GUM_REG_XAX, sizeof (gpointer));
  gum_code_writer_put_mov_fs_u32_ptr_reg (&cw, TIB_OFFSET_STACK, GUM_REG_XAX);

  /* overwrite caller's return address so we can trap the return */
  gum_code_writer_put_mov_reg_address (&cw, GUM_REG_XAX,
      GUM_ADDRESS (leave_trampoline));
  gum_code_writer_put_mov_reg_ptr_reg (&cw, GUM_REG_XSP, GUM_REG_XAX);

  /* finally execute the original instructions and resume execution */
  gum_relocator_init (&rl, (guint8 *) func->details.address, &cw);
  do
  {
    reloc_size = gum_relocator_read_one (&rl, NULL);
    g_assert_cmpuint (reloc_size, !=, 0);
  }
  while (reloc_size < REDIRECT_SIZE);
  gum_relocator_write_all (&rl);
  gum_relocator_free (&rl);
  func->disp_size = reloc_size;

  if (!gum_relocator_eoi (&rl))
  {
    gum_code_writer_put_jmp (&cw,
        (guint8 *) func->details.address + func->disp_size);
  }

  /* setup_stack: allocate a new stack */
  gum_code_writer_put_label (&cw, setup_stack_lbl);
  gum_code_writer_put_mov_reg_address (&cw, GUM_REG_XCX,
      GUM_ADDRESS (&priv->next_stack));
  gum_code_writer_put_mov_reg_u32 (&cw, GUM_REG_EAX, sizeof (gpointer));
  gum_code_writer_put_lock_xadd_reg_ptr_reg (&cw, GUM_REG_XCX, GUM_REG_EAX);
  gum_code_writer_put_mov_reg_reg_ptr (&cw, GUM_REG_EAX, GUM_REG_XAX);
  gum_code_writer_put_mov_fs_u32_ptr_reg (&cw, TIB_OFFSET_STACK, GUM_REG_EAX);
  gum_code_writer_put_jmp_short_label (&cw, stack_acq_lbl);

  g_assert_cmpuint (gum_code_writer_offset (&cw), <=, ENTER_MAX_SIZE);
  gum_tracer_shrink_code (self, code, gum_code_writer_offset (&cw));

  gum_code_writer_free (&cw);

  return code;
}

static guint8 *
gum_tracer_create_leave_trampoline (GumTracer * self,
                                    GumTracerFunction * func)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);
  guint8 * code;
  GumCodeWriter cw;

  code = gum_tracer_alloc_code (self, LEAVE_MAX_SIZE);
  gum_code_writer_init (&cw, code);

  gum_code_writer_put_push_reg (&cw, GUM_REG_XAX);
  /* FIXME: we should also store edx for 64 bit return type */

  /* log */
  gum_tracer_write_logging_code (self, func, GUM_TRAMPOLINE_LEAVE, &cw);

  /* then jump back to caller */
  gum_code_writer_put_mov_reg_fs_u32_ptr (&cw, GUM_REG_ECX, TIB_OFFSET_STACK);
  gum_code_writer_put_sub_reg_imm (&cw, GUM_REG_ECX, 4);
  gum_code_writer_put_mov_fs_u32_ptr_reg (&cw, TIB_OFFSET_STACK, GUM_REG_ECX);

  gum_code_writer_put_pop_reg (&cw, GUM_REG_XAX);

  gum_code_writer_put_jmp_reg_ptr (&cw, GUM_REG_XCX);

  g_assert_cmpuint (gum_code_writer_offset (&cw), <=, LEAVE_MAX_SIZE);
  gum_tracer_shrink_code (self, code, gum_code_writer_offset (&cw));

  gum_code_writer_free (&cw);

  return code;
}

static void
gum_tracer_write_logging_code (GumTracer * self,
                               GumTracerFunction * func,
                               GumTrampolineKind kind,
                               GumCodeWriter * cw)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);
  GumRingBuffer * rb = priv->ringbuf;
  const guint block_size = sizeof (GumTraceEntry);
  const gchar * check_can_write_lbl = "check_can_write";
  guint arglist_size;
  guint num_data_blocks;

  if (kind == GUM_TRAMPOLINE_ENTER && func->details.arglist_size > 0)
    arglist_size = func->details.arglist_size;
  else
    arglist_size = 0;

  /* we'll append arglist data in one or more trailing blocks */
  num_data_blocks = GUM_TRACER_SIZE_TO_BLOCKS (arglist_size);

  /* atomically increment writepos */
  gum_code_writer_put_mov_reg_address (cw, GUM_REG_XCX,
      GUM_ADDRESS (&rb->writepos));
  gum_code_writer_put_mov_reg_u32 (cw, GUM_REG_EAX, 1 + num_data_blocks);
  gum_code_writer_put_lock_xadd_reg_ptr_reg (cw, GUM_REG_XCX, GUM_REG_EAX);

  /* make sure we write behind readpos */
  gum_code_writer_put_label (cw, check_can_write_lbl);
  gum_code_writer_put_mov_reg_address (cw, GUM_REG_XCX,
      GUM_ADDRESS (&rb->readpos));
  gum_code_writer_put_mov_reg_reg_ptr (cw, GUM_REG_ECX, GUM_REG_XCX);
  gum_code_writer_put_sub_reg_reg (cw, GUM_REG_ECX, GUM_REG_EAX);
  gum_code_writer_put_cmp_reg_i32 (cw, GUM_REG_ECX,
      -(GUM_TRACER_BUFFER_SIZE - (gint) num_data_blocks));
  gum_code_writer_put_jle_label (cw, check_can_write_lbl, GUM_UNLIKELY);

  if (num_data_blocks > 0)
  {
    guint block_idx, total_remainder;
    gint8 sp_offset = 4;

    /* save starting index for later */
    gum_code_writer_put_mov_reg_reg (cw, GUM_REG_EDX, GUM_REG_EAX);

    total_remainder = arglist_size;

    for (block_idx = 0; block_idx < num_data_blocks; block_idx++)
    {
      guint block_offset = 0;
      guint block_remainder = MIN (total_remainder, block_size);
      guint inc_idx;

      /* restore starting index */
      if (block_idx > 0)
        gum_code_writer_put_mov_reg_reg (cw, GUM_REG_EAX, GUM_REG_EDX);

      /* adjust to the current block index -- block 0 is used for header */
      for (inc_idx = 0; inc_idx < block_idx + 1; inc_idx++)
        gum_code_writer_put_inc_reg (cw, GUM_REG_EAX);

      gum_tracer_write_conversion_from_xax_index_to_address (self, cw);

      while (block_remainder >= 16)
      {
        gum_code_writer_put_movdqu_xmm0_esp_offset_ptr (cw, sp_offset);
        gum_code_writer_put_movdqu_eax_offset_ptr_xmm0 (cw, block_offset);

        sp_offset += 16;
        block_offset += 16;
        block_remainder -= 16;
      }

      if (block_remainder >= 8)
      {
        gum_code_writer_put_movq_xmm0_esp_offset_ptr (cw, sp_offset);
        gum_code_writer_put_movq_eax_offset_ptr_xmm0 (cw, block_offset);

        sp_offset += 8;
        block_offset += 8;
        block_remainder -= 8;
      }

      if (block_remainder >= 4)
      {
        gum_code_writer_put_mov_reg_reg_offset_ptr (cw, GUM_REG_ECX,
            GUM_REG_ESP, sp_offset);
        gum_code_writer_put_mov_reg_offset_ptr_reg (cw,
            GUM_REG_XAX, block_offset, GUM_REG_ECX);

        sp_offset += 4;
        block_offset += 4;
        block_remainder -= 4;
      }

      total_remainder -= block_offset;
    }

    /* restore starting index */
    gum_code_writer_put_mov_reg_reg (cw, GUM_REG_EAX, GUM_REG_EDX);
  }

  gum_tracer_write_conversion_from_xax_index_to_address (self, cw);

  /* fill in name_id */
  gum_code_writer_put_mov_reg_offset_ptr_u32 (cw,
      GUM_REG_XAX, GT_ENTRY_OFFSET (name_id), func->name_id);

  /* fill in thread_id */
  gum_code_writer_put_mov_reg_fs_u32_ptr (cw, GUM_REG_ECX,
      TIB_OFFSET_CUR_THREAD_ID);
  gum_code_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XAX, GT_ENTRY_OFFSET (thread_id),
      GUM_REG_ECX);

  /* fill in depth and modify it */
  gum_code_writer_put_mov_reg_fs_u32_ptr (cw, GUM_REG_ECX, TIB_OFFSET_DEPTH);
  if (kind == GUM_TRAMPOLINE_LEAVE)
    gum_code_writer_put_dec_reg (cw, GUM_REG_ECX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XAX, GT_ENTRY_OFFSET (depth),
      GUM_REG_ECX);
  if (kind == GUM_TRAMPOLINE_ENTER)
    gum_code_writer_put_inc_reg (cw, GUM_REG_ECX);
  gum_code_writer_put_mov_fs_u32_ptr_reg (cw, TIB_OFFSET_DEPTH, GUM_REG_ECX);

  /* fill in timestamp */
  gum_code_writer_put_push_reg (cw, GUM_REG_XAX);
  gum_code_writer_put_call (cw, priv->get_time_impl);
  gum_code_writer_put_mov_reg_reg (cw, GUM_REG_ECX, GUM_REG_EAX);
  gum_code_writer_put_pop_reg (cw, GUM_REG_XAX);
  gum_code_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XAX, GT_ENTRY_OFFSET (timestamp),
      GUM_REG_ECX);

  /* fill in arglist_size */
  gum_code_writer_put_mov_reg_offset_ptr_u32 (cw,
      GUM_REG_XAX, GT_ENTRY_OFFSET (arglist_size),
      arglist_size);

  /* fill in type, which implicitly seals off the entry */
  gum_code_writer_put_mov_reg_offset_ptr_u32 (cw,
      GUM_REG_XAX, GT_ENTRY_OFFSET (type),
      (kind == GUM_TRAMPOLINE_ENTER) ? GUM_ENTRY_ENTER : GUM_ENTRY_LEAVE);
}

static void
gum_tracer_write_conversion_from_xax_index_to_address (GumTracer * self,
                                                       GumCodeWriter * cw)
{
  /*
   * xax % GUM_TRACER_BUFFER_SIZE, avoiding idiv to save a few cycles
   *
   * Note that on 64 bit this also serves the purpose of zeroing out
   * the 32 upper bits...
   */
  gum_code_writer_put_and_reg_u32 (cw, GUM_REG_XAX,
      GUM_TRACER_BUFFER_SIZE - 1);

  /* multiply by sizeof (GumTraceEntry) */
  gum_code_writer_put_shl_reg_u8 (cw, GUM_REG_EAX,
      GUM_TRACE_ENTRY_SIZE_IN_POT);

  /* add base address */
#if GLIB_SIZEOF_VOID_P == 4
  gum_code_writer_put_add_reg_imm (cw, GUM_REG_EAX,
      (gint32) self->priv->ringbuf->entries);
#else
  gum_code_writer_put_push_reg (cw, GUM_REG_RCX);
  gum_code_writer_put_mov_reg_address (cw, GUM_REG_RCX,
      GUM_ADDRESS (self->priv->ringbuf->entries));
  gum_code_writer_put_add_reg_reg (cw, GUM_REG_RAX, GUM_REG_RCX);
  gum_code_writer_put_pop_reg (cw, GUM_REG_RCX);
#endif
}

static gpointer
gum_tracer_resolve (GumTracer * self,
                    gpointer address)
{
  while (TRUE)
  {
    gpointer target;

    if (gum_tracer_knows_function_at (self, address))
      return NULL;

    target = gum_code_reader_try_get_relative_jump_target (address);
    if (target == NULL)
      target = gum_code_reader_try_get_indirect_jump_target (address);

    if (target != NULL)
      address = target;
    else
      break;
  }

  return address;
}

static void
gum_tracer_create_stacks (GumTracer * self)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);
  guint i;

  for (i = 0; i < GUM_MAX_THREADS; i++)
  {
    priv->stacks[i] =
        gum_alloc_n_pages (GUM_TRACER_STACK_SIZE_IN_PAGES, GUM_PAGE_RW);
  }

  priv->next_stack = priv->stacks;
}

static void
gum_tracer_free_stacks (GumTracer * self)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);
  guint i;

  for (i = 0; i < GUM_MAX_THREADS; i++)
  {
    gum_free_pages (priv->stacks[i]);
  }
}

static guint8 *
gum_tracer_alloc_code (GumTracer * self,
                       guint size)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);
  gpointer result = NULL;
  gint i;
  GumCodePage * cp = NULL;

  size = GUM_ALIGN (size, GUM_CODE_ALIGNMENT);

  for (i = priv->code_pages->len - 1; i >= 0 && result == NULL; i--)
  {
    cp = &g_array_index (priv->code_pages, GumCodePage, i);

    if (cp->offset + size <= priv->page_size)
    {
      result = cp->data + cp->offset;
      cp->offset += size;
    }
  }

  if (result == NULL)
  {
    result = gum_alloc_n_pages (1, GUM_PAGE_RWX);
    g_array_set_size (priv->code_pages, priv->code_pages->len + 1);
    cp = &g_array_index (priv->code_pages, GumCodePage,
        priv->code_pages->len - 1);
    cp->data = result;
    cp->offset = size;
  }

  memset (result, 0xcc, size);

  priv->last_alloc_cp = cp;
  priv->last_alloc_address = result;
  priv->last_alloc_size = size;

  return result;
}

static void
gum_tracer_shrink_code (GumTracer * self,
                        gpointer address,
                        guint new_size)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);

  new_size = GUM_ALIGN (new_size, GUM_CODE_ALIGNMENT);

  g_assert (address == priv->last_alloc_address);
  g_assert (new_size <= priv->last_alloc_size);

  priv->last_alloc_cp->offset -= priv->last_alloc_size - new_size;
}

static void
gum_tracer_free_code_pages (GumTracer * self)
{
  GumTracerPrivate * priv = GUM_TRACER_GET_PRIVATE (self);
  guint i;

  for (i = 0; i < priv->code_pages->len; i++)
  {
    GumCodePage * cp = &g_array_index (priv->code_pages, GumCodePage, i);
    gum_free_pages (cp->data);
  }

  g_array_free (priv->code_pages, TRUE);
}

