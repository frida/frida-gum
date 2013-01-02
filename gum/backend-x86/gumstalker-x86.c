/*
 * Copyright (C) 2009-2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C)      2010 Karl Trygve Kalleberg <karltk@boblycat.org>
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

#define ENABLE_DEBUG 0

#include "gumstalker.h"

#include "gumx86writer.h"
#include "gummemory.h"
#include "gumx86relocator.h"
#include "gumspinlock.h"
#include "gumudis86.h"

#ifdef G_OS_WIN32
#include "backend-windows/gumwinexceptionhook.h"

#define VC_EXTRALEAN
#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#endif

#define GUM_MAX_EXEC_BLOCKS                    2
#define GUM_EXEC_BLOCK_SIZE_IN_PAGES          20
#define GUM_EXEC_BLOCK_MAX_MAPPINGS         2048
#define GUM_MAX_INSTRUMENTATION_MAPPING_COUNT  2
#define GUM_MAX_INSTRUMENTATION_WRAPPER_SIZE 256

typedef struct _GumCallProbe GumCallProbe;

typedef struct _GumExecCtx GumExecCtx;
typedef struct _GumExecBlock GumExecBlock;

typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumAddressMapping GumAddressMapping;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;

typedef guint GumVirtualizationRequirements;

struct _GumStalkerPrivate
{
  guint page_size;

  GPrivate * exec_ctx;

  volatile gboolean any_probes_attached;
  volatile gint last_probe_id;
  GumSpinlock probe_lock;
  GHashTable * probe_target_by_id;
  GHashTable * probe_array_by_address;

#ifdef G_OS_WIN32
  gpointer user32_start, user32_end;
  gpointer ki_user_callback_dispatcher_impl;
#endif
};

struct _GumCallProbe
{
  GumProbeId id;
  GumCallProbeCallback callback;
  gpointer user_data;
  GDestroyNotify user_notify;
};

struct _GumExecCtx
{
  GumStalker * stalker;

  GumX86Writer code_writer;
  GumX86Relocator relocator;

  GumEventSink * sink;
  GumEventType sink_mask;
  gpointer sink_process_impl; /* cached */
  GumEvent tmp_event;

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;
  gint call_depth;

  gpointer thunks;
  gpointer jmp_block_thunk;
  gpointer ret_block_thunk;
  gpointer replace_block_thunk;
  gpointer replacement_address;

  guint8 * block_pool;
  guint block_pool_size;
  guint block_size;
  guint block_code_offset;
  guint block_code_maxsize;
};

struct _GumAddressMapping
{
  gpointer replica_address;
  gpointer real_address;
};

struct _GumExecBlock
{
  GumExecCtx * ctx;

  guint8 * real_begin;
  guint8 * real_end;

  guint8 * code_begin;
  guint8 * code_end;

  GumAddressMapping mappings[GUM_EXEC_BLOCK_MAX_MAPPINGS];
  guint mappings_len;

  guint8 state;

#ifdef G_OS_WIN32
  DWORD previous_dr0;
  DWORD previous_dr1;
  DWORD previous_dr2;
  DWORD previous_dr7;
#endif
};

enum _GumExecState
{
  GUM_EXEC_NORMAL,
  GUM_EXEC_SINGLE_STEPPING_ON_CALL,
  GUM_EXEC_SINGLE_STEPPING_THROUGH_CALL
};

struct _GumGeneratorContext
{
  GumInstruction * instruction;
  GumX86Relocator * relocator;
  GumX86Writer * code_writer;
  gpointer continuation_real_address;
};

struct _GumInstruction
{
  ud_t * ud;
  guint8 * begin;
  guint8 * end;
};

struct _GumBranchTarget
{
  gpointer origin_ip;

  gpointer absolute_address;
  gssize relative_offset;

  gboolean is_indirect;
  uint8_t pfx_seg;
  enum ud_type base;
  enum ud_type index;
  guint8 scale;
};

enum _GumVirtualizationRequirements
{
  GUM_REQUIRE_NOTHING         = 0,

  GUM_REQUIRE_MAPPING         = 1 << 0,
  GUM_REQUIRE_RELOCATION      = 1 << 1,
  GUM_REQUIRE_SINGLE_STEP     = 1 << 2
};

#define GUM_STALKER_GET_PRIVATE(o) ((o)->priv)

#if GLIB_SIZEOF_VOID_P == 4
#define STATE_PRESERVE_SIZE (5 * sizeof (gpointer))
#define STATE_PRESERVE_TOPMOST_REGISTER_INDEX (3)
#else
#define STATE_PRESERVE_SIZE (11 * sizeof (gpointer))
#define STATE_PRESERVE_TOPMOST_REGISTER_INDEX (9)
#endif
#define GUM_THUNK_ARGLIST_STACK_RESERVE 64

static void gum_stalker_finalize (GObject * object);

void _gum_stalker_do_follow_me (GumStalker * self, GumEventSink * sink,
    gpointer * ret_addr_ptr);

static void gum_stalker_free_probe_array (gpointer data);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumEventSink * sink);
static void gum_stalker_destroy_exec_ctx (GumStalker * self, GumExecCtx * ctx);
static GumExecCtx * gum_stalker_get_exec_ctx (GumStalker * self);
static gpointer GUM_THUNK gum_exec_ctx_replace_current_block_with (
    GumExecCtx * ctx, gpointer start_address);
static void gum_exec_ctx_create_thunks (GumExecCtx * ctx);
static void gum_exec_ctx_destroy_thunks (GumExecCtx * ctx);
static void gum_exec_ctx_create_block_pool (GumExecCtx * ctx);
static void gum_exec_ctx_destroy_block_pool (GumExecCtx * ctx);

static GumExecBlock * gum_exec_ctx_create_block_for (GumExecCtx * ctx,
    gpointer address);
static void gum_exec_ctx_write_call_event_code (GumExecCtx * ctx,
    gpointer location, const GumBranchTarget * target, GumX86Writer * cw);
static void gum_exec_ctx_write_ret_event_code (GumExecCtx * ctx,
    gpointer location, GumX86Writer * cw);
static void gum_exec_ctx_write_exec_event_code (GumExecCtx * ctx,
    gpointer location, GumX86Writer * cw);
static void gum_exec_ctx_write_event_init_code (GumExecCtx * ctx,
    GumEventType type, GumX86Writer * cw);
static void gum_exec_ctx_write_event_submit_code (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_write_state_preserve_prolog (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_write_state_preserve_epilog (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_write_depth_increment_code (GumExecCtx * ctx,
    GumX86Writer * cw);
static void gum_exec_ctx_write_depth_decrement_code (GumExecCtx * ctx,
    GumX86Writer * cw);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static void gum_exec_block_free (GumExecBlock * block);
static gboolean gum_exec_block_full (GumExecBlock * block);
static GumVirtualizationRequirements gum_exec_block_virtualize_branch_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_ret_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_sysenter_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static void gum_exec_block_write_call_invoke_code (GumExecBlock * block,
    GumInstruction * insn, const GumBranchTarget * target, GumX86Writer * cw);
static void gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
    const GumBranchTarget * target, GumX86Writer * cw);
static void gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
    gpointer orig_ret_insn, GumX86Writer * cw);
static void gum_exec_block_write_single_step_transfer_code (
    GumExecBlock * block, GumGeneratorContext * gc);
static void gum_exec_block_write_call_probe_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_add_address_mapping (GumExecBlock * block,
    gpointer replica_address, gpointer real_address);
static gpointer gum_exec_block_get_real_address_of (GumExecBlock * block,
    gpointer address);

static void gum_write_push_branch_target_address (
    const GumBranchTarget * target, guint state_preserve_stack_offset,
    guint accumulated_stack_delta, GumX86Writer * cw);
static void gum_load_real_register_into (GumCpuReg target_register,
    GumCpuReg source_register, guint state_preserve_stack_offset,
    guint accumulated_stack_delta, gpointer ip, GumX86Writer * cw);
static void gum_write_segment_prefix (uint8_t segment, GumX86Writer * cw);

static GumCpuReg gum_cpu_meta_reg_from_real_reg (GumCpuReg reg);
static GumCpuReg gum_cpu_reg_from_ud (enum ud_type reg);

#ifdef G_OS_WIN32
static gboolean gum_stalker_handle_exception (
    EXCEPTION_RECORD * exception_record, CONTEXT * context,
    gpointer user_data);
#endif

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT);

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumStalkerPrivate));

  object_class->finalize = gum_stalker_finalize;
}

static void
gum_stalker_init (GumStalker * self)
{
  GumStalkerPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_STALKER, GumStalkerPrivate);
  priv = GUM_STALKER_GET_PRIVATE (self);

  gum_spinlock_init (&priv->probe_lock);
  priv->probe_target_by_id =
      g_hash_table_new_full (NULL, NULL, NULL, NULL);
  priv->probe_array_by_address =
      g_hash_table_new_full (NULL, NULL, NULL, gum_stalker_free_probe_array);

#if defined (G_OS_WIN32) && GLIB_SIZEOF_VOID_P == 4
  gum_win_exception_hook_add (gum_stalker_handle_exception, self);

  {
    HMODULE ntmod, usermod;
    MODULEINFO mi;
    BOOL success;
    gboolean found_user32_code = FALSE;
    guint8 * p;

    ntmod = GetModuleHandle (_T ("ntdll.dll"));
    usermod = GetModuleHandle (_T ("user32.dll"));
    g_assert (ntmod != NULL && usermod != NULL);

    success = GetModuleInformation (GetCurrentProcess (), usermod,
        &mi, sizeof (mi));
    g_assert (success);
    priv->user32_start = mi.lpBaseOfDll;
    priv->user32_end = (guint8 *) mi.lpBaseOfDll + mi.SizeOfImage;

    for (p = (guint8 *) priv->user32_start; p < (guint8 *) priv->user32_end;)
    {
      MEMORY_BASIC_INFORMATION mbi;

      success = VirtualQuery (p, &mbi, sizeof (mbi)) == sizeof (mbi);
      g_assert (success);

      if (mbi.Protect == PAGE_EXECUTE_READ ||
          mbi.Protect == PAGE_EXECUTE_READWRITE ||
          mbi.Protect == PAGE_EXECUTE_WRITECOPY)
      {
        priv->user32_start = mbi.BaseAddress;
        priv->user32_end = (guint8 *) mbi.BaseAddress + mbi.RegionSize;

        found_user32_code = TRUE;
      }

      p = (guint8 *) mbi.BaseAddress + mbi.RegionSize;
    }

    g_assert (found_user32_code);

    priv->ki_user_callback_dispatcher_impl = GUM_FUNCPTR_TO_POINTER (
        GetProcAddress (ntmod, "KiUserCallbackDispatcher"));
    g_assert (priv->ki_user_callback_dispatcher_impl != NULL);
  }
#endif

  priv->page_size = gum_query_page_size ();
  priv->exec_ctx = g_private_new (NULL);
}

static void
gum_stalker_finalize (GObject * object)
{
  GumStalker * self = GUM_STALKER (object);

#if defined (G_OS_WIN32) && GLIB_SIZEOF_VOID_P == 4
  gum_win_exception_hook_remove (gum_stalker_handle_exception);
#endif

  g_hash_table_unref (self->priv->probe_array_by_address);
  g_hash_table_unref (self->priv->probe_target_by_id);

  gum_spinlock_free (&self->priv->probe_lock);

  G_OBJECT_CLASS (gum_stalker_parent_class)->finalize (object);
}

GumStalker *
gum_stalker_new (void)
{
  return GUM_STALKER (g_object_new (GUM_TYPE_STALKER, NULL));
}

#ifdef _MSC_VER

#define RETURN_ADDRESS_POINTER_FROM_FIRST_ARGUMENT(arg)   \
    ((gpointer *) ((volatile guint8 *) &arg - sizeof (gpointer)))

void
gum_stalker_follow_me (GumStalker * self,
                       GumEventSink * sink)
{
  volatile gpointer * ret_addr_ptr;

  ret_addr_ptr = RETURN_ADDRESS_POINTER_FROM_FIRST_ARGUMENT (self);

  _gum_stalker_do_follow_me (self, sink, ret_addr_ptr);
}

#endif

void
_gum_stalker_do_follow_me (GumStalker * self,
                           GumEventSink * sink,
                           gpointer * ret_addr_ptr)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_create_exec_ctx (self, sink);
  ctx->current_block = gum_exec_ctx_create_block_for (ctx, *ret_addr_ptr);
  *ret_addr_ptr = ctx->current_block->code_begin;
}

void
gum_stalker_unfollow_me (GumStalker * self)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  g_assert (ctx != NULL);

  g_assert (ctx->unfollow_called_while_still_following);

  gum_stalker_destroy_exec_ctx (self, ctx);
}

gboolean
gum_stalker_is_following_me (GumStalker * self)
{
  return gum_stalker_get_exec_ctx (self) != NULL;
}

GumProbeId
gum_stalker_add_call_probe (GumStalker * self,
                            gpointer target_address,
                            GumCallProbeCallback callback,
                            gpointer data,
                            GDestroyNotify notify)
{
  GumStalkerPrivate * priv = self->priv;
  GumCallProbe probe;
  GArray * probes;

  probe.id = g_atomic_int_exchange_and_add (&priv->last_probe_id, 1) + 1;
  probe.callback = callback;
  probe.user_data = data;
  probe.user_notify = notify;

  gum_spinlock_acquire (&priv->probe_lock);

  g_hash_table_insert (priv->probe_target_by_id, GSIZE_TO_POINTER (probe.id),
      target_address);

  probes = (GArray *)
      g_hash_table_lookup (priv->probe_array_by_address, target_address);
  if (probes == NULL)
  {
    probes = g_array_sized_new (FALSE, FALSE, sizeof (GumCallProbe), 4);
    g_hash_table_insert (priv->probe_array_by_address, target_address, probes);
  }

  g_array_append_val (probes, probe);

  priv->any_probes_attached = TRUE;

  gum_spinlock_release (&priv->probe_lock);

  return probe.id;
}

void
gum_stalker_remove_call_probe (GumStalker * self,
                               GumProbeId id)
{
  GumStalkerPrivate * priv = self->priv;
  gpointer target_address;

  gum_spinlock_acquire (&priv->probe_lock);

  target_address =
      g_hash_table_lookup (priv->probe_target_by_id, GSIZE_TO_POINTER (id));
  if (target_address != NULL)
  {
    GArray * probes;
    gint match_index = -1;
    guint i;
    GumCallProbe * probe;

    g_hash_table_remove (priv->probe_target_by_id, GSIZE_TO_POINTER (id));

    probes = (GArray *)
        g_hash_table_lookup (priv->probe_array_by_address, target_address);
    g_assert (probes != NULL);

    for (i = 0; i != probes->len; i++)
    {
      if (g_array_index (probes, GumCallProbe, i).id == id)
      {
        match_index = i;
        break;
      }
    }
    g_assert_cmpint (match_index, !=, -1);

    probe = &g_array_index (probes, GumCallProbe, match_index);
    if (probe->user_notify != NULL)
      probe->user_notify (probe->user_data);
    g_array_remove_index (probes, match_index);

    if (probes->len == 0)
      g_hash_table_remove (priv->probe_array_by_address, target_address);

    priv->any_probes_attached =
        g_hash_table_size (priv->probe_array_by_address) != 0;
  }

  gum_spinlock_release (&priv->probe_lock);
}

static void
gum_stalker_free_probe_array (gpointer data)
{
  GArray * probes = (GArray *) data;
  guint i;

  for (i = 0; i != probes->len; i++)
  {
    GumCallProbe * probe = &g_array_index (probes, GumCallProbe, i);
    if (probe->user_notify != NULL)
      probe->user_notify (probe->user_data);
  }

  g_array_free (probes, TRUE);
}

static GumExecCtx *
gum_stalker_create_exec_ctx (GumStalker * self,
                             GumEventSink * sink)
{
  GumExecCtx * ctx;

  ctx = g_new0 (GumExecCtx, 1);

  ctx->stalker = g_object_ref (self);

  gum_x86_writer_init (&ctx->code_writer, NULL);
  gum_x86_relocator_init (&ctx->relocator, NULL, &ctx->code_writer);

  ctx->sink = g_object_ref (sink);
  ctx->sink_mask = gum_event_sink_query_mask (sink);
  ctx->sink_process_impl = GUM_FUNCPTR_TO_POINTER (
      GUM_EVENT_SINK_GET_INTERFACE (sink)->process);

  gum_exec_ctx_create_thunks (ctx);
  gum_exec_ctx_create_block_pool (ctx);

  g_private_set (self->priv->exec_ctx, ctx);

  gum_event_sink_start (sink);

  return ctx;
}

static void
gum_stalker_destroy_exec_ctx (GumStalker * self,
                              GumExecCtx * ctx)
{
  gum_event_sink_stop (ctx->sink);

  gum_exec_ctx_destroy_block_pool (ctx);
  gum_exec_ctx_destroy_thunks (ctx);

  g_object_unref (ctx->sink);

  gum_x86_relocator_free (&ctx->relocator);
  gum_x86_writer_free (&ctx->code_writer);

  g_object_unref (ctx->stalker);

  g_free (ctx);

  g_private_set (self->priv->exec_ctx, NULL);
}

static GumExecCtx *
gum_stalker_get_exec_ctx (GumStalker * self)
{
  return (GumExecCtx *) g_private_get (self->priv->exec_ctx);
}

static gpointer GUM_THUNK
gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
                                         gpointer start_address)
{
  if (start_address == gum_stalker_unfollow_me)
  {
    ctx->unfollow_called_while_still_following = TRUE;
    return start_address;
  }

  gum_exec_block_free (ctx->current_block);
  ctx->current_block = gum_exec_ctx_create_block_for (ctx, start_address);

  return ctx->current_block->code_begin;
}

static void
gum_exec_ctx_create_thunks (GumExecCtx * ctx)
{
  GumX86Writer cw;

  g_assert (ctx->thunks == NULL);

  ctx->thunks = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_x86_writer_init (&cw, ctx->thunks);

  ctx->jmp_block_thunk = gum_x86_writer_cur (&cw);
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP,
      GUM_THUNK_ARGLIST_STACK_RESERVE);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_XBX, STATE_PRESERVE_SIZE,
      GUM_REG_XAX);
  gum_exec_ctx_write_state_preserve_epilog (ctx, &cw);
  gum_x86_writer_put_ret (&cw);

  ctx->ret_block_thunk = gum_x86_writer_cur (&cw);
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP,
      GUM_THUNK_ARGLIST_STACK_RESERVE);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_XBX, sizeof (gpointer) + STATE_PRESERVE_SIZE,
      GUM_REG_XAX);
  gum_exec_ctx_write_state_preserve_epilog (ctx, &cw);
  gum_x86_writer_put_ret (&cw);

  ctx->replace_block_thunk = gum_x86_writer_cur (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX); /* placeholder */
  gum_exec_ctx_write_state_preserve_prolog (ctx, &cw);
  gum_x86_writer_put_mov_reg_address (&cw, GUM_REG_XDX,
      GUM_ADDRESS (&ctx->replacement_address));
  gum_x86_writer_put_mov_reg_reg_ptr (&cw, GUM_THUNK_REG_ARG1, GUM_REG_XDX);
  gum_x86_writer_put_mov_reg_address (&cw, GUM_THUNK_REG_ARG0,
      GUM_ADDRESS (ctx));
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, /* x64 ABI compat */
      GUM_THUNK_ARGLIST_STACK_RESERVE);
  gum_x86_writer_put_call (&cw,
      GUM_FUNCPTR_TO_POINTER (gum_exec_ctx_replace_current_block_with));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP,
      GUM_THUNK_ARGLIST_STACK_RESERVE);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw,
      GUM_REG_XBX, STATE_PRESERVE_SIZE,
      GUM_REG_XAX);
  gum_exec_ctx_write_state_preserve_epilog (ctx, &cw);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_free (&cw);
}

static void
gum_exec_ctx_destroy_thunks (GumExecCtx * ctx)
{
  gum_free_pages (ctx->thunks);
}

static void
gum_exec_ctx_create_block_pool (GumExecCtx * ctx)
{
  ctx->block_pool_size = GUM_MAX_EXEC_BLOCKS * GUM_EXEC_BLOCK_SIZE_IN_PAGES;
  ctx->block_pool = gum_alloc_n_pages (ctx->block_pool_size, GUM_PAGE_RWX);
  ctx->block_pool_size *= ctx->stalker->priv->page_size;

  ctx->block_size =
      GUM_EXEC_BLOCK_SIZE_IN_PAGES * ctx->stalker->priv->page_size;
  g_assert (ctx->block_size >= 2 * sizeof (GumExecBlock));
  ctx->block_code_offset = ((sizeof (GumExecBlock) + (64 - 1)) & ~(64 - 1));
  ctx->block_code_maxsize = ctx->block_size - ctx->block_code_offset;
}

static void
gum_exec_ctx_destroy_block_pool (GumExecCtx * ctx)
{
  gum_free_pages (ctx->block_pool);
}

static gpointer
gum_exec_ctx_resolve_code_address (GumExecCtx * ctx,
                                   gpointer address)
{
  guint8 * addr = address;

  if (addr >= ctx->current_block->code_begin &&
      addr < ctx->current_block->code_end)
  {
    return gum_exec_block_get_real_address_of (ctx->current_block, address);
  }

  return address;
}

#if ENABLE_DEBUG

static void
gum_disasm (guint8 * code, guint size, const gchar * prefix)
{
  ud_t ud_obj;

  ud_init (&ud_obj);
  ud_set_input_buffer (&ud_obj, code, size);
  ud_set_mode (&ud_obj, GUM_CPU_MODE);
  ud_set_pc (&ud_obj, GPOINTER_TO_SIZE (code));
  ud_set_syntax (&ud_obj, UD_SYN_INTEL);

  while (ud_disassemble (&ud_obj))
  {
    printf ("%s%p\t%s\n", prefix, code + ud_insn_off (&ud_obj),
        ud_insn_asm (&ud_obj));
  }
}

#endif

static GumExecBlock *
gum_exec_ctx_create_block_for (GumExecCtx * ctx,
                               gpointer address)
{
  GumExecBlock * block;
  GumX86Writer * cw = &ctx->code_writer;
  GumX86Relocator * rl = &ctx->relocator;
  GumGeneratorContext gc;

  block = gum_exec_block_new (ctx);
  gum_x86_writer_reset (cw, block->code_begin);
  gum_x86_relocator_reset (rl, address, cw);

  gc.instruction = NULL;
  gc.relocator = rl;
  gc.code_writer = cw;
  gc.continuation_real_address = NULL;

#if ENABLE_DEBUG
  printf ("\n\n***\n\nCreating block for %p:\n", address);
#endif

  do
  {
    guint n_read;
    GumInstruction insn;
    GumVirtualizationRequirements requirements = GUM_REQUIRE_NOTHING;

    n_read = gum_x86_relocator_read_one (rl, NULL);
    g_assert_cmpuint (n_read, !=, 0);

    insn.ud = gum_x86_relocator_peek_next_write_insn (rl);
    insn.begin = gum_x86_relocator_peek_next_write_source (rl);
    insn.end = insn.begin + ud_insn_len (insn.ud);

    g_assert (insn.ud != NULL && insn.begin != NULL);

#if ENABLE_DEBUG
    gum_disasm (insn.begin, insn.end - insn.begin, "");
#endif

    gc.instruction = &insn;

    if ((ctx->sink_mask & GUM_EXEC) != 0)
      gum_exec_ctx_write_exec_event_code (ctx, insn.begin, cw);

    switch (insn.ud->mnemonic)
    {
      case UD_Icall:
      case UD_Ijmp:
        requirements = gum_exec_block_virtualize_branch_insn (block, &gc);
        break;
      case UD_Iret:
        requirements = gum_exec_block_virtualize_ret_insn (block, &gc);
        break;
      case UD_Isysenter:
        requirements = gum_exec_block_virtualize_sysenter_insn (block, &gc);
        break;
      default:
        if (gum_mnemonic_is_jcc (insn.ud->mnemonic))
          requirements = gum_exec_block_virtualize_branch_insn (block, &gc);
        else
          requirements = GUM_REQUIRE_RELOCATION;
        break;
    }

    if ((requirements & GUM_REQUIRE_RELOCATION) != 0)
    {
      if ((requirements & GUM_REQUIRE_MAPPING) != 0)
      {
        gum_exec_block_add_address_mapping (block, gum_x86_writer_cur (cw),
            insn.begin);
      }

      gum_x86_relocator_write_one_no_label (rl);

      if ((requirements & GUM_REQUIRE_MAPPING) != 0)
      {
        gum_exec_block_add_address_mapping (block, gum_x86_writer_cur (cw),
            insn.end);
      }
    }
    else if ((requirements & GUM_REQUIRE_SINGLE_STEP) != 0)
    {
      gum_x86_relocator_skip_one_no_label (rl);
      gum_exec_block_write_single_step_transfer_code (block, &gc);
    }

#if ENABLE_DEBUG
    {
      guint8 * begin = block->code_end;
      block->code_end = gum_x86_writer_cur (cw);
      gum_disasm (begin, block->code_end - begin, "\t");
    }
#else
    block->code_end = gum_x86_writer_cur (cw);
#endif

    if (gum_exec_block_full (block))
    {
      gc.continuation_real_address = insn.end;
      break;
    }
  }
  while (!gum_x86_relocator_eob (rl));

  if (gc.continuation_real_address != NULL)
  {
    GumBranchTarget continue_target = { 0, };

    continue_target.is_indirect = FALSE;
    continue_target.absolute_address = gc.continuation_real_address;

    gum_exec_block_write_jmp_transfer_code (block, &continue_target, cw);
  }

  gum_x86_writer_put_int3 (cw); /* should never get here */

  gum_x86_writer_flush (cw);

  block->code_end = (guint8 *) gum_x86_writer_cur (cw);

  block->real_begin = (guint8 *) rl->input_start;
  block->real_end = (guint8 *) rl->input_cur;

  g_assert_cmpuint (gum_x86_writer_offset (cw), <=, ctx->block_code_maxsize);

  block->code_end--; /* pretend the INT3 guard isn't part of the block */

  return block;
}

static void
gum_exec_ctx_write_call_event_code (GumExecCtx * ctx,
                                    gpointer location,
                                    const GumBranchTarget * target,
                                    GumX86Writer * cw)
{
  gum_exec_ctx_write_state_preserve_prolog (ctx, cw);

  gum_exec_ctx_write_event_init_code (ctx, GUM_CALL, cw);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX,
      GUM_ADDRESS (location));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XAX, G_STRUCT_OFFSET (GumCallEvent, location),
      GUM_REG_XCX);

  gum_write_push_branch_target_address (target, 0, STATE_PRESERVE_SIZE, cw);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XCX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XAX, G_STRUCT_OFFSET (GumCallEvent, target),
      GUM_REG_XCX);

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX,
      GUM_ADDRESS (&ctx->call_depth));
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_REG_XCX, GUM_REG_XCX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XAX, G_STRUCT_OFFSET (GumCallEvent, depth),
      GUM_REG_XCX);

  gum_exec_ctx_write_event_submit_code (ctx, cw);

  gum_exec_ctx_write_state_preserve_epilog (ctx, cw);
}

static void
gum_exec_ctx_write_ret_event_code (GumExecCtx * ctx,
                                   gpointer location,
                                   GumX86Writer * cw)
{
  gum_exec_ctx_write_state_preserve_prolog (ctx, cw);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_REG_XAX,
      GUM_REG_XBX, STATE_PRESERVE_SIZE);
  gum_x86_writer_put_call_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (gum_exec_ctx_resolve_code_address), 2,
      GUM_ARG_POINTER, ctx,
      GUM_ARG_REGISTER, GUM_REG_XAX);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XDX, GUM_REG_XAX);

  gum_exec_ctx_write_event_init_code (ctx, GUM_RET, cw);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX,
      GUM_ADDRESS (location));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XAX, G_STRUCT_OFFSET (GumRetEvent, location),
      GUM_REG_XCX);

  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XAX, G_STRUCT_OFFSET (GumRetEvent, target),
      GUM_REG_XDX);

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX,
      GUM_ADDRESS (&ctx->call_depth));
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_REG_ECX, GUM_REG_XCX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XAX, G_STRUCT_OFFSET (GumCallEvent, depth),
      GUM_REG_ECX);

  gum_exec_ctx_write_event_submit_code (ctx, cw);

  gum_exec_ctx_write_state_preserve_epilog (ctx, cw);
}

static void
gum_exec_ctx_write_exec_event_code (GumExecCtx * ctx,
                                    gpointer location,
                                    GumX86Writer * cw)
{
  gum_exec_ctx_write_state_preserve_prolog (ctx, cw);

  gum_exec_ctx_write_event_init_code (ctx, GUM_EXEC, cw);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX,
      GUM_ADDRESS (location));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XAX, G_STRUCT_OFFSET (GumExecEvent, location),
      GUM_REG_XCX);

  gum_exec_ctx_write_event_submit_code (ctx, cw);

  gum_exec_ctx_write_state_preserve_epilog (ctx, cw);
}

static void
gum_exec_ctx_write_event_init_code (GumExecCtx * ctx,
                                    GumEventType type,
                                    GumX86Writer * cw)
{
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (&ctx->tmp_event));
  gum_x86_writer_put_mov_reg_offset_ptr_u32 (cw,
      GUM_REG_XAX, G_STRUCT_OFFSET (GumAnyEvent, type),
      type);
}

static void
gum_exec_ctx_write_event_submit_code (GumExecCtx * ctx,
                                      GumX86Writer * cw)
{
#if GLIB_SIZEOF_VOID_P == 4
  guint align_correction = 8;
  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, align_correction);
#endif
  gum_x86_writer_put_call_with_arguments (cw,
      ctx->sink_process_impl, 2,
      GUM_ARG_POINTER, ctx->sink,
      GUM_ARG_REGISTER, GUM_REG_XAX);
#if GLIB_SIZEOF_VOID_P == 4
  gum_x86_writer_put_add_reg_imm (cw, GUM_REG_XSP, align_correction);
#endif
}

static void
gum_exec_ctx_write_state_preserve_prolog (GumExecCtx * ctx,
                                          GumX86Writer * cw)
{
  guint8 fxsave[] = {
    0x0f, 0xae, 0x04, 0x24 /* fxsave [esp] */
  };

  (void) ctx;

  gum_x86_writer_put_pushfx (cw);

  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XCX);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XDX);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XBX);

#if GLIB_SIZEOF_VOID_P == 8
  gum_x86_writer_put_push_reg (cw, GUM_REG_XSI);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XDI);
  gum_x86_writer_put_push_reg (cw, GUM_REG_R8);
  gum_x86_writer_put_push_reg (cw, GUM_REG_R9);
  gum_x86_writer_put_push_reg (cw, GUM_REG_R10);
  gum_x86_writer_put_push_reg (cw, GUM_REG_R11);
#endif

  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XBX, GUM_REG_XSP);
  gum_x86_writer_put_and_reg_u32 (cw, GUM_REG_XSP, ~(16 - 1));
  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, 512);
  gum_x86_writer_put_bytes (cw, fxsave, sizeof (fxsave));
}

static void
gum_exec_ctx_write_state_preserve_epilog (GumExecCtx * ctx,
                                          GumX86Writer * cw)
{
  guint8 fxrstor[] = {
    0x0f, 0xae, 0x0c, 0x24 /* fxrstor [esp] */
  };

  (void) ctx;

  gum_x86_writer_put_bytes (cw, fxrstor, sizeof (fxrstor));
  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XSP, GUM_REG_XBX);

#if GLIB_SIZEOF_VOID_P == 8
  gum_x86_writer_put_pop_reg (cw, GUM_REG_R11);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_R10);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_R9);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_R8);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XDI);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XSI);
#endif

  gum_x86_writer_put_pop_reg (cw, GUM_REG_XBX);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XDX);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XCX);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XAX);

  gum_x86_writer_put_popfx (cw);
}

static void
gum_exec_ctx_write_depth_increment_code (GumExecCtx * ctx,
    GumX86Writer * cw)
{
  gum_x86_writer_put_pushfx (cw);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (&ctx->call_depth));
  gum_x86_writer_put_inc_reg_ptr (cw, GUM_PTR_DWORD, GUM_REG_XAX);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XAX);
  gum_x86_writer_put_popfx (cw);
}

static void
gum_exec_ctx_write_depth_decrement_code (GumExecCtx * ctx,
    GumX86Writer * cw)
{
  gum_x86_writer_put_pushfx (cw);
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (&ctx->call_depth));
  gum_x86_writer_put_dec_reg_ptr (cw, GUM_PTR_DWORD, GUM_REG_XAX);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XAX);
  gum_x86_writer_put_popfx (cw);
}

static GumExecBlock *
gum_exec_block_new (GumExecCtx * ctx)
{
  guint8 * cur;
  guint i;

  cur = ctx->block_pool;

  for (i = 0; i < GUM_MAX_EXEC_BLOCKS; ++i)
  {
    GumExecBlock * block = (GumExecBlock *) cur;

    if (block->ctx == NULL)
    {
      block->ctx = ctx;

      block->code_end = block->code_begin = cur + ctx->block_code_offset;

      block->mappings_len = 0;
      block->state = GUM_EXEC_NORMAL;

      /* TODO: should we fill the block with INT3 instructions? */

      return block;
    }

    cur += ctx->block_size;
  }

  g_assert_not_reached ();
  return NULL;
}

static void
gum_exec_block_free (GumExecBlock * block)
{
  block->ctx = NULL;
}

static gboolean
gum_exec_block_full (GumExecBlock * block)
{
  guint mappings_available, bytes_available;

  mappings_available = G_N_ELEMENTS (block->mappings) - block->mappings_len;
  bytes_available =
      block->ctx->block_size - (block->code_end - (guint8 *) block);
  return (mappings_available < GUM_MAX_INSTRUMENTATION_MAPPING_COUNT) ||
      (bytes_available < GUM_MAX_INSTRUMENTATION_WRAPPER_SIZE);
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_branch_insn (GumExecBlock * block,
                                       GumGeneratorContext * gc)
{
  GumInstruction * insn = gc->instruction;
  GumX86Writer * cw = gc->code_writer;
  gboolean is_conditional;
  ud_operand_t * op = &insn->ud->operand[0];
  GumBranchTarget target = { 0, };

  is_conditional =
      (insn->ud->mnemonic != UD_Icall && insn->ud->mnemonic != UD_Ijmp);

  target.origin_ip = insn->end;

  target.pfx_seg = UD_NONE;
  target.base = op->base;
  target.index = op->index;
  target.scale = op->scale;

  if (op->type == UD_OP_JIMM && op->base == UD_NONE)
  {
    if (op->size == 8)
      target.absolute_address = insn->end + op->lval.sbyte;
    else if (op->size == 32)
      target.absolute_address = insn->end + op->lval.sdword;
    else
      g_assert_not_reached ();
    target.is_indirect = FALSE;
  }
  else if (op->type == UD_OP_MEM)
  {
    g_assert (op->size == GLIB_SIZEOF_VOID_P * 8);
#if GLIB_SIZEOF_VOID_P == 4
    g_assert (op->base == UD_NONE ||
        (op->base >= UD_R_EAX && op->base <= UD_R_EDI));
#else
    g_assert (op->base == UD_NONE || op->base == UD_R_RIP ||
        (op->base >= UD_R_RAX && op->base <= UD_R_R15));
#endif
    g_assert (op->offset == 8 || op->offset == 32 || op->offset == 0);

#ifdef G_OS_WIN32
    /* Can't follow WoW64 */
    if (insn->ud->pfx_seg == UD_R_FS && op->lval.udword == 0xc0)
      return GUM_REQUIRE_SINGLE_STEP;
#endif

    if (op->base == UD_NONE && op->index == UD_NONE)
    {
      g_assert (op->offset == 32);
      target.absolute_address = GSIZE_TO_POINTER (op->lval.udword);
    }
    else
    {
      if (op->offset == 8)
        target.relative_offset = op->lval.sbyte;
      else if (op->offset == 32)
        target.relative_offset = op->lval.sdword;
      else
        target.relative_offset = 0;
    }

    target.is_indirect = TRUE;
    target.pfx_seg = insn->ud->pfx_seg;
  }
  else if (op->type == UD_OP_REG)
  {
    target.is_indirect = FALSE;
  }
  else
  {
    g_assert_not_reached ();
  }

  gum_x86_relocator_skip_one_no_label (gc->relocator);

  if (insn->ud->mnemonic == UD_Icall)
  {
    if ((block->ctx->sink_mask & GUM_CALL) != 0)
      gum_exec_ctx_write_call_event_code (block->ctx, insn->begin, &target, cw);

    if (block->ctx->stalker->priv->any_probes_attached)
      gum_exec_block_write_call_probe_code (block, &target, gc);

    if ((block->ctx->sink_mask & (GUM_CALL | GUM_RET)) != 0)
      gum_exec_ctx_write_depth_increment_code (block->ctx, cw);

    gum_exec_block_write_call_invoke_code (block, insn, &target, cw);
  }
  else
  {
    gpointer cond_false_lbl_id;
    
    cond_false_lbl_id =
        GUINT_TO_POINTER ((GPOINTER_TO_UINT (insn->begin) << 16) | 0xbeef);

    if (is_conditional)
    {
      g_assert (!target.is_indirect);

      gum_x86_writer_put_jcc_short_label (cw,
          gum_jcc_opcode_negate (gum_jcc_insn_to_short_opcode (insn->begin)),
          cond_false_lbl_id, GUM_NO_HINT);
    }

    gum_exec_block_write_jmp_transfer_code (block, &target, cw);

    if (is_conditional)
    {
      GumBranchTarget cond_target = { 0, };

      cond_target.is_indirect = FALSE;
      cond_target.absolute_address = insn->end;

      gum_x86_writer_put_label (cw, cond_false_lbl_id);
      gum_exec_block_write_jmp_transfer_code (block, &cond_target, cw);
    }
  }

  return GUM_REQUIRE_NOTHING;
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_ret_insn (GumExecBlock * block,
                                    GumGeneratorContext * gc)
{
  if ((block->ctx->sink_mask & GUM_RET) != 0)
  {
    guint8 * insn_start;

    insn_start = gum_x86_relocator_peek_next_write_source (gc->relocator);

    gum_exec_ctx_write_ret_event_code (block->ctx, insn_start,
        gc->code_writer);
  }

  gum_x86_relocator_skip_one_no_label (gc->relocator);

  if ((block->ctx->sink_mask & (GUM_CALL | GUM_RET)) != 0)
    gum_exec_ctx_write_depth_decrement_code (block->ctx, gc->code_writer);

  gum_exec_block_write_ret_transfer_code (block, gc->instruction->begin,
      gc->code_writer);

  return GUM_REQUIRE_NOTHING;
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_sysenter_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
#if defined (HAVE_MAC) && GLIB_SIZEOF_VOID_P == 4
  guint8 code[] = {
    0x89, 0x15, 0x78, 0x56, 0x34, 0x12, /* mov [X], edx */
    0xba, 0x78, 0x56, 0x34, 0x12,       /* mov edx, X */
    0x0f, 0x34                          /* sysenter */
  };
  *((gpointer *) (code + 2)) = &block->ctx->replacement_address;
  *((gpointer *) (code + 7)) = block->ctx->replace_block_thunk;

  if ((block->ctx->sink_mask & (GUM_CALL | GUM_RET)) != 0)
    gum_exec_ctx_write_depth_decrement_code (block->ctx, gc->code_writer);
  gum_x86_writer_put_bytes (gc->code_writer, code, sizeof (code));
  gum_x86_relocator_skip_one_no_label (gc->relocator);

  return GUM_REQUIRE_NOTHING;
#else
  return GUM_REQUIRE_RELOCATION;
#endif
}

static void
gum_exec_block_write_call_invoke_code (GumExecBlock * block,
                                       GumInstruction * insn,
                                       const GumBranchTarget * target,
                                       GumX86Writer * cw)
{
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* placeholder: retaddr */

  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* placeholder: blockaddr */
  gum_exec_ctx_write_state_preserve_prolog (block->ctx, cw);

  /* fill in retaddr placeholder now that we can safely clobber CPU state */
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (insn->end));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XBX, STATE_PRESERVE_SIZE + sizeof (gpointer),
      GUM_REG_XAX);

  /* arguments, fastcall-style */
  gum_write_push_branch_target_address (target, 0,
      STATE_PRESERVE_SIZE + 2 * sizeof (gpointer), cw);
  gum_x86_writer_put_pop_reg (cw, GUM_THUNK_REG_ARG1);
  gum_x86_writer_put_mov_reg_address (cw, GUM_THUNK_REG_ARG0,
      GUM_ADDRESS (block->ctx));
  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, /* x64 ABI compat */
      GUM_THUNK_ARGLIST_STACK_RESERVE);

  /* push fake return address so we chain to jmp_block_thunk */
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (block->ctx->jmp_block_thunk));
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);

  /* jump */
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (gum_exec_ctx_replace_current_block_with));
  gum_x86_writer_put_jmp_reg (cw, GUM_REG_XAX);
}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        GumX86Writer * cw)
{
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* placeholder: blockaddr */
  gum_exec_ctx_write_state_preserve_prolog (block->ctx, cw);

  /* arguments, fastcall-style */
  gum_write_push_branch_target_address (target, 0,
      STATE_PRESERVE_SIZE + sizeof (gpointer), cw);
  gum_x86_writer_put_pop_reg (cw, GUM_THUNK_REG_ARG1);
  gum_x86_writer_put_mov_reg_address (cw, GUM_THUNK_REG_ARG0,
      GUM_ADDRESS (block->ctx));
  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, /* x64 ABI compat */
      GUM_THUNK_ARGLIST_STACK_RESERVE);

  /* push fake return address so we chain to jmp_block_thunk */
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (block->ctx->jmp_block_thunk));
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);

  /* jump */
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (gum_exec_ctx_replace_current_block_with));
  gum_x86_writer_put_jmp_reg (cw, GUM_REG_XAX);
}

static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        gpointer orig_ret_insn,
                                        GumX86Writer * cw)
{
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* placeholder */
  gum_exec_ctx_write_state_preserve_prolog (block->ctx, cw);

  /* fill in placeholder now that we can safely clobber CPU state */
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (orig_ret_insn));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_REG_XBX, STATE_PRESERVE_SIZE,
      GUM_REG_XAX);

  /* arguments, fastcall-style */
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw,
      GUM_THUNK_REG_ARG1,
      GUM_REG_XBX, STATE_PRESERVE_SIZE + sizeof (gpointer));
  gum_x86_writer_put_mov_reg_address (cw, GUM_THUNK_REG_ARG0,
      GUM_ADDRESS (block->ctx));
  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, /* x64 ABI compat */
      GUM_THUNK_ARGLIST_STACK_RESERVE);

  /* push fake return address so we chain to ret_block_thunk */
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (block->ctx->ret_block_thunk));
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);

  /* jump */
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (gum_exec_ctx_replace_current_block_with));
  gum_x86_writer_put_jmp_reg (cw, GUM_REG_XAX);
}

static void
gum_exec_block_write_single_step_transfer_code (GumExecBlock * block,
                                                GumGeneratorContext * gc)
{
  guint8 code[] = {
    0xc6, 0x05, 0x78, 0x56, 0x34, 0x12,       /* mov byte [X], state */
          GUM_EXEC_SINGLE_STEPPING_ON_CALL,
    0x9c,                                     /* pushfd              */
    0x81, 0x0c, 0x24, 0x00, 0x01, 0x00, 0x00, /* or [esp], 0x100     */
    0x9d                                      /* popfd               */
  };

  *((guint8 **) (code + 2)) = &block->state;
  gum_x86_writer_put_bytes (gc->code_writer, code, sizeof (code));
  gum_x86_writer_put_jmp (gc->code_writer, gc->instruction->begin);
}

static void
gum_exec_block_invoke_call_probes_for_target (GumExecBlock * block,
                                              gpointer target_address,
                                              GumCpuContext * cpu_context)
{
  GumStalkerPrivate * priv = block->ctx->stalker->priv;
  GArray * probes;

  gum_spinlock_acquire (&priv->probe_lock);

  probes = (GArray *)
      g_hash_table_lookup (priv->probe_array_by_address, target_address);
  if (probes != NULL)
  {
    GumCallSite call_site;
    guint i;

    call_site.block_address = block->real_begin;
#if GLIB_SIZEOF_VOID_P == 4
    call_site.stack_data = GSIZE_TO_POINTER (cpu_context->esp + 4);
#else
    call_site.stack_data = GSIZE_TO_POINTER (cpu_context->rsp + 8);
#endif
    call_site.cpu_context = cpu_context;

    for (i = 0; i != probes->len; i++)
    {
      GumCallProbe * probe = &g_array_index (probes, GumCallProbe, i);

      probe->callback (&call_site, probe->user_data);
    }
  }

  gum_spinlock_release (&priv->probe_lock);
}

static void
gum_exec_block_write_call_probe_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc)
{
  GumX86Writer * cw = gc->code_writer;
  guint state_preserve_stack_offset, accumulated_stack_delta = 0;
  guint8 fxsave[] = {
    0x0f, 0xae, 0x04, 0x24 /* fxsave [esp] */
  };
  guint8 fxrstor[] = {
    0x0f, 0xae, 0x0c, 0x24 /* fxrstor [esp] */
  };
#if GLIB_SIZEOF_VOID_P == 4
  guint align_correction = 4;

  state_preserve_stack_offset = G_STRUCT_OFFSET (GumCpuContext, ebx);
#else
  state_preserve_stack_offset = G_STRUCT_OFFSET (GumCpuContext, r9);
#endif

  gum_x86_writer_put_pushfx (cw);
  accumulated_stack_delta += sizeof (gpointer);

  gum_x86_writer_put_pushax (cw); /* all of GumCpuContext except for xip */
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
      GUM_ADDRESS (gc->instruction->begin));
  gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* GumCpuContext.xip */
  accumulated_stack_delta += sizeof (GumCpuContext);

  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XBX, GUM_REG_XSP);
  gum_x86_writer_put_and_reg_u32 (cw, GUM_REG_XSP, ~(16 - 1));
  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, 512);
  gum_x86_writer_put_bytes (cw, fxsave, sizeof (fxsave));

  gum_write_push_branch_target_address (target, state_preserve_stack_offset,
      accumulated_stack_delta, cw);
  gum_x86_writer_put_pop_reg (cw, GUM_REG_XSI);

#if GLIB_SIZEOF_VOID_P == 4
  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XSP, align_correction);
#endif
  gum_x86_writer_put_call_with_arguments (cw,
      GUM_FUNCPTR_TO_POINTER (gum_exec_block_invoke_call_probes_for_target), 3,
      GUM_ARG_POINTER, block,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XBX);
#if GLIB_SIZEOF_VOID_P == 4
  gum_x86_writer_put_add_reg_imm (cw, GUM_REG_XSP, align_correction);
#endif

  gum_x86_writer_put_bytes (cw, fxrstor, sizeof (fxrstor));
  gum_x86_writer_put_mov_reg_reg (cw, GUM_REG_XSP, GUM_REG_XBX);

  gum_x86_writer_put_pop_reg (cw, GUM_REG_XAX); /* discard
                                                    GumCpuContext.xip */
  gum_x86_writer_put_popax (cw);
  gum_x86_writer_put_popfx (cw);
}

static void
gum_exec_block_add_address_mapping (GumExecBlock * block,
                                    gpointer replica_address,
                                    gpointer real_address)
{
  GumAddressMapping * map = &block->mappings[block->mappings_len++];
  g_assert_cmpuint (block->mappings_len, <=, G_N_ELEMENTS (block->mappings));
  map->replica_address = replica_address;
  map->real_address = real_address;
}

static gpointer
gum_exec_block_get_real_address_of (GumExecBlock * block,
                                    gpointer address)
{
  guint i;

  for (i = 0; i < block->mappings_len; ++i)
  {
    const GumAddressMapping * cur = &block->mappings[i];
    if (cur->replica_address == address)
      return cur->real_address;
  }

  g_assert_not_reached ();
  return NULL;
}

static void
gum_write_push_branch_target_address (const GumBranchTarget * target,
                                      guint state_preserve_stack_offset,
                                      guint accumulated_stack_delta,
                                      GumX86Writer * cw)
{
  if (!target->is_indirect)
  {
    if (target->base == UD_NONE)
    {
      gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);
      gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX,
          GUM_ADDRESS (target->absolute_address));
      gum_x86_writer_put_xchg_reg_reg_ptr (cw, GUM_REG_XAX, GUM_REG_XSP);
    }
    else
    {
      gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);
      gum_load_real_register_into (GUM_REG_XAX,
          gum_cpu_reg_from_ud (target->base),
          state_preserve_stack_offset,
          accumulated_stack_delta,
          target->origin_ip,
          cw);
      gum_x86_writer_put_xchg_reg_reg_ptr (cw, GUM_REG_XAX, GUM_REG_XSP);
    }
  }
  else if (target->base == UD_NONE && target->index == UD_NONE)
  {
    g_assert (target->scale == 0);
    g_assert (target->absolute_address != NULL);
    g_assert (target->relative_offset == 0);

    gum_write_segment_prefix (target->pfx_seg, cw);
    gum_x86_writer_put_byte (cw, 0xff);
    gum_x86_writer_put_byte (cw, 0x35);
    gum_x86_writer_put_bytes (cw, (guint8 *) &target->absolute_address,
        sizeof (target->absolute_address));
  }
  else
  {
    gum_x86_writer_put_push_reg (cw, GUM_REG_XAX); /* placeholder */

    gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);
    gum_x86_writer_put_push_reg (cw, GUM_REG_XDX);

    gum_load_real_register_into (GUM_REG_XAX,
        gum_cpu_reg_from_ud (target->base),
        state_preserve_stack_offset,
        accumulated_stack_delta,
        target->origin_ip,
        cw);
    gum_load_real_register_into (GUM_REG_XDX,
        gum_cpu_reg_from_ud (target->index),
        state_preserve_stack_offset,
        accumulated_stack_delta,
        target->origin_ip,
        cw);
    gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr (cw, GUM_REG_XAX,
        GUM_REG_XAX, GUM_REG_XDX, target->scale ? target->scale : 1,
        target->relative_offset);
    gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
        GUM_REG_XSP, 2 * sizeof (gpointer),
        GUM_REG_XAX);

    gum_x86_writer_put_pop_reg (cw, GUM_REG_XDX);
    gum_x86_writer_put_pop_reg (cw, GUM_REG_XAX);
  }
}

static void
gum_load_real_register_into (GumCpuReg target_register,
                             GumCpuReg source_register,
                             guint state_preserve_stack_offset,
                             guint accumulated_stack_delta,
                             gpointer ip,
                             GumX86Writer * cw)
{
  GumCpuReg source_meta;

  source_meta = gum_cpu_meta_reg_from_real_reg (source_register);

  if (source_meta >= GUM_REG_XAX && source_meta <= GUM_REG_XBX)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, target_register,
        GUM_REG_XBX, state_preserve_stack_offset +
        STATE_PRESERVE_TOPMOST_REGISTER_INDEX * sizeof (gpointer) -
        ((source_meta - GUM_REG_XAX) * sizeof (gpointer)));
  }
  else if (source_meta == GUM_REG_XSP)
  {
    gum_x86_writer_put_lea_reg_reg_offset (cw, target_register,
        GUM_REG_XBX, accumulated_stack_delta);
  }
  else if (source_meta == GUM_REG_XIP)
  {
    gum_x86_writer_put_mov_reg_address (cw, target_register,
        GUM_ADDRESS (ip));
  }
  else if (source_meta == GUM_REG_NONE)
  {
    gum_x86_writer_put_xor_reg_reg (cw, target_register, target_register);
  }
  else
  {
    gum_x86_writer_put_mov_reg_reg (cw, target_register, source_register);
  }
}

static void
gum_write_segment_prefix (uint8_t segment,
                          GumX86Writer * cw)
{
  switch (segment)
  {
    case UD_NONE: break;

    case UD_R_CS: gum_x86_writer_put_byte (cw, 0x2e); break;
    case UD_R_SS: gum_x86_writer_put_byte (cw, 0x36); break;
    case UD_R_DS: gum_x86_writer_put_byte (cw, 0x3e); break;
    case UD_R_ES: gum_x86_writer_put_byte (cw, 0x26); break;
    case UD_R_FS: gum_x86_writer_put_byte (cw, 0x64); break;
    case UD_R_GS: gum_x86_writer_put_byte (cw, 0x65); break;

    default:
      g_assert_not_reached ();
      break;
  }
}

static GumCpuReg
gum_cpu_meta_reg_from_real_reg (GumCpuReg reg)
{
  if (reg >= GUM_REG_EAX && reg <= GUM_REG_R15D)
    return (GumCpuReg) (GUM_REG_XAX + reg - GUM_REG_EAX);
  else if (reg >= GUM_REG_RAX && reg <= GUM_REG_R15)
    return (GumCpuReg) (GUM_REG_XAX + reg - GUM_REG_RAX);
  else if (reg == GUM_REG_RIP)
    return GUM_REG_XIP;
  else if (reg == GUM_REG_NONE)
    return GUM_REG_NONE;

  g_assert_not_reached ();
  return GUM_REG_NONE;
}

static GumCpuReg
gum_cpu_reg_from_ud (enum ud_type reg)
{
  if (reg >= UD_R_EAX && reg <= UD_R_EDI)
    return (GumCpuReg) (GUM_REG_EAX + reg - UD_R_EAX);
  else if (reg >= UD_R_RAX && reg <= UD_R_R15)
    return (GumCpuReg) (GUM_REG_RAX + reg - UD_R_RAX);
  else if (reg == UD_R_RIP)
    return GUM_REG_RIP;
  else if (reg == UD_NONE)
    return GUM_REG_NONE;
  else
    g_assert_not_reached ();
}

#ifdef G_OS_WIN32

#ifdef _M_IX86

static void
enable_hardware_breakpoint (DWORD * dr7_reg, guint index)
{
  /* set both RWn and LENn to 00 */
  *dr7_reg &= ~(0xf << (16 + (2 * index)));

  /* set LE bit */
  *dr7_reg |= 1 << (2 * index);
}

static gpointer
find_system_call_above_us (GumStalker * stalker, gpointer * start_esp)
{
  GumStalkerPrivate * priv = stalker->priv;
  gpointer * top_esp, * cur_esp;
  guint8 call_fs_c0_code[] = { 0x64, 0xff, 0x15, 0xc0, 0x00, 0x00, 0x00 };
  guint8 * minimum_address, * maximum_address;

  __asm
  {
    mov eax, fs:[4];
    mov [top_esp], eax;
  }

  if ((guint) ABS (top_esp - start_esp) > priv->page_size)
  {
    top_esp = (gpointer *) ((GPOINTER_TO_SIZE (start_esp) +
        (priv->page_size - 1)) & ~(priv->page_size - 1));
  }

  /* These boundaries are quite artificial... */
  minimum_address = (guint8 *) priv->user32_start + sizeof (call_fs_c0_code);
  maximum_address = (guint8 *) priv->user32_end - 1;

  for (cur_esp = start_esp + 1; cur_esp < top_esp; cur_esp++)
  {
    guint8 * address = (guint8 *) *cur_esp;

    if (address >= minimum_address && address <= maximum_address &&
        memcmp (address - sizeof (call_fs_c0_code), call_fs_c0_code,
        sizeof (call_fs_c0_code)) == 0)
    {
      return address;
    }
  }

  return NULL;
}

#endif

static gboolean
gum_stalker_handle_exception (EXCEPTION_RECORD * exception_record,
    CONTEXT * context, gpointer user_data)
{
  GumStalker * self = GUM_STALKER_CAST (user_data);
  GumExecCtx * ctx;
  GumExecBlock * block;

  if (exception_record->ExceptionCode != STATUS_SINGLE_STEP)
    return FALSE;

  ctx = gum_stalker_get_exec_ctx (self);
  if (ctx == NULL)
    return FALSE;

  block = ctx->current_block;

#ifdef _M_IX86
  /*printf ("gum_stalker_handle_exception state=%u %p %08x\n",
      block->state, context->Eip, exception_record->ExceptionCode);*/

  switch (block->state)
  {
    case GUM_EXEC_SINGLE_STEPPING_ON_CALL:
    {
      DWORD instruction_after_call_here;
      DWORD instruction_after_call_above_us;

      block->previous_dr0 = context->Dr0;
      block->previous_dr1 = context->Dr1;
      block->previous_dr2 = context->Dr2;
      block->previous_dr7 = context->Dr7;

      instruction_after_call_here = context->Eip +
          gum_find_instruction_length ((guint8 *) context->Eip);
      context->Dr0 = instruction_after_call_here;
      enable_hardware_breakpoint (&context->Dr7, 0);

      context->Dr1 = (DWORD) self->priv->ki_user_callback_dispatcher_impl;
      enable_hardware_breakpoint (&context->Dr7, 1);

      instruction_after_call_above_us = (DWORD)
          find_system_call_above_us (self, (gpointer *) context->Esp);
      if (instruction_after_call_above_us != 0)
      {
        context->Dr2 = instruction_after_call_above_us;
        enable_hardware_breakpoint (&context->Dr7, 2);
      }

      block->state = GUM_EXEC_SINGLE_STEPPING_THROUGH_CALL;

      break;
    }

    case GUM_EXEC_SINGLE_STEPPING_THROUGH_CALL:
    {
      context->Dr0 = block->previous_dr0;
      context->Dr1 = block->previous_dr1;
      context->Dr2 = block->previous_dr2;
      context->Dr7 = block->previous_dr7;

      ctx->replacement_address = (gpointer) context->Eip;
      context->Eip = (DWORD) ctx->replace_block_thunk;

      block->state = GUM_EXEC_NORMAL;

      break;
    }

    case GUM_EXEC_NORMAL:
      return FALSE;

    default:
      g_assert_not_reached ();
  }
#else
  (void) context;
#endif

  return TRUE;
}

#endif
