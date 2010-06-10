/*
 * Copyright (C) 2009-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumstalker.h"

#include "gumcodewriter.h"
#include "gummemory.h"
#include "gumrelocator.h"
#include "gumudis86.h"

#ifdef G_OS_WIN32
#include "backend-windows/gumwinexceptionhook.h"

#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#endif

#define GUM_MAX_EXEC_BLOCKS                 2048
#define GUM_EXEC_BLOCK_SIZE_IN_PAGES          16
#define GUM_EXEC_BLOCK_MAX_MAPPINGS         2048
#define GUM_MAX_INSTRUMENTATION_MAPPING_COUNT  2
#define GUM_MAX_INSTRUMENTATION_WRAPPER_SIZE 256

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

#ifdef G_OS_WIN32
  gpointer user32_start, user32_end;
  gpointer ki_user_callback_dispatcher_impl;
#endif
};

struct _GumExecCtx
{
  GumStalker * stalker;

  GumCodeWriter code_writer;
  GumRelocator relocator;

  GumEventSink * sink;
  GumEventType sink_mask;
  gpointer sink_process_impl; /* cached */
  GumEvent tmp_event;

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
  GumRelocator * relocator;
  GumCodeWriter * code_writer;
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

#define CDECL_PRESERVE_SIZE (4 * sizeof (gpointer))

static void gum_stalker_finalize (GObject * object);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumEventSink * sink);
static void gum_stalker_destroy_exec_ctx (GumStalker * self, GumExecCtx * ctx);
static GumExecCtx * gum_stalker_get_exec_ctx (GumStalker * self);
static gpointer GUM_STDCALL gum_exec_ctx_replace_current_block_with (
    GumExecCtx * ctx, gpointer start_address);
static void gum_exec_ctx_create_thunks (GumExecCtx * ctx);
static void gum_exec_ctx_destroy_thunks (GumExecCtx * ctx);
static void gum_exec_ctx_create_block_pool (GumExecCtx * ctx);
static void gum_exec_ctx_destroy_block_pool (GumExecCtx * ctx);

static GumExecBlock * gum_exec_ctx_create_block_for (GumExecCtx * ctx,
    gpointer address);
static void gum_exec_ctx_write_call_event_code (GumExecCtx * ctx,
    gpointer location, const GumBranchTarget * target, GumCodeWriter * cw);
static void gum_exec_ctx_write_ret_event_code (GumExecCtx * ctx,
    gpointer location, GumCodeWriter * cw);
static void gum_exec_ctx_write_exec_event_code (GumExecCtx * ctx,
    gpointer location, GumCodeWriter * cw);
static void gum_exec_ctx_write_event_init_code (GumExecCtx * ctx,
    GumEventType type, GumCodeWriter * cw);
static void gum_exec_ctx_write_event_submit_code (GumExecCtx * ctx,
    GumCodeWriter * cw);
static void gum_exec_ctx_write_cdecl_preserve_prolog (GumExecCtx * ctx,
    GumCodeWriter * cw);
static void gum_exec_ctx_write_cdecl_preserve_epilog (GumExecCtx * ctx,
    GumCodeWriter * cw);
static void gum_exec_ctx_write_depth_increment_code (GumExecCtx * ctx,
    GumCodeWriter * cw);
static void gum_exec_ctx_write_depth_decrement_code (GumExecCtx * ctx,
    GumCodeWriter * cw);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static void gum_exec_block_free (GumExecBlock * block);
static gboolean gum_exec_block_full (GumExecBlock * block);
static GumVirtualizationRequirements gum_exec_block_virtualize_branch_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_ret_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static void gum_exec_block_write_call_invoke_code (GumExecBlock * block,
    GumInstruction * insn, const GumBranchTarget * target, GumCodeWriter * cw);
static void gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
    const GumBranchTarget * target, GumCodeWriter * cw);
static void gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
    gpointer orig_ret_insn, GumCodeWriter * cw);
static void gum_exec_block_write_single_step_transfer_code (
    GumExecBlock * block, GumGeneratorContext * gc);
static void gum_exec_block_add_address_mapping (GumExecBlock * block,
    gpointer replica_address, gpointer real_address);
static gpointer gum_exec_block_get_real_address_of (GumExecBlock * block,
    gpointer address);
static gpointer gum_exec_block_get_real_address_of_last_instruction (
    GumExecBlock * block);

static void gum_write_push_branch_target_address (
    const GumBranchTarget * target, guint cdecl_preserve_stack_offset,
    guint accumulated_stack_delta, GumCodeWriter * cw);
static void gum_load_real_register_into (enum ud_type target_register,
    enum ud_type source_register, guint8 cdecl_preserve_stack_offset,
    guint accumulated_stack_delta, GumCodeWriter * cw);
static void gum_write_segment_prefix (uint8_t segment, GumCodeWriter * cw);

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

#ifdef G_OS_WIN32
  gum_win_exception_hook_add (gum_stalker_handle_exception, self);

  {
    HMODULE ntmod, usermod;
    MODULEINFO mi;
    BOOL success;

    ntmod = GetModuleHandle (_T ("ntdll.dll"));
    usermod = GetModuleHandle (_T ("user32.dll"));
    g_assert (ntmod != NULL && usermod != NULL);

    success = GetModuleInformation (GetCurrentProcess (), usermod,
        &mi, sizeof (mi));
    g_assert (success);
    priv->user32_start = mi.lpBaseOfDll;
    priv->user32_end = (guint8 *) mi.lpBaseOfDll + mi.SizeOfImage;

    priv->ki_user_callback_dispatcher_impl =
        GetProcAddress (ntmod, "KiUserCallbackDispatcher");
    g_assert (priv->ki_user_callback_dispatcher_impl != NULL);
  }
#endif

  priv->page_size = gum_query_page_size ();
  priv->exec_ctx = g_private_new (NULL);
}

static void
gum_stalker_finalize (GObject * object)
{
#ifdef G_OS_WIN32
  gum_win_exception_hook_remove (gum_stalker_handle_exception);
#endif

  G_OBJECT_CLASS (gum_stalker_parent_class)->finalize (object);
}

GumStalker *
gum_stalker_new (void)
{
  return GUM_STALKER (g_object_new (GUM_TYPE_STALKER, NULL));
}

void
gum_stalker_follow_me (GumStalker * self,
                       GumEventSink * sink)
{
  gpointer * ret_addr_ptr, start_address;
  GumExecCtx * ctx;

  ret_addr_ptr = (gpointer *) (((gssize) &self) - sizeof (GumStalker *));
  start_address = *ret_addr_ptr;

  ctx = gum_stalker_create_exec_ctx (self, sink);
  ctx->current_block = gum_exec_ctx_create_block_for (ctx, start_address);
  *ret_addr_ptr = ctx->current_block->code_begin;
}

void
gum_stalker_unfollow_me (GumStalker * self)
{
  gpointer * ret_addr_ptr, ret_addr;
  GumExecCtx * ctx;

  ret_addr_ptr = (gpointer *) (((gssize) &self) - sizeof (GumStalker *));
  ret_addr = *ret_addr_ptr;

  ctx = gum_stalker_get_exec_ctx (self);

  g_assert (ret_addr == ctx->current_block->code_end);

  *ret_addr_ptr =
      gum_exec_block_get_real_address_of (ctx->current_block, ret_addr);

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
                            GumCallProbeCallback handler,
                            gpointer data)
{
  return 1;
}

void
gum_stalker_remove_call_probe (GumStalker * self,
                               GumProbeId id)
{
}

static GumExecCtx *
gum_stalker_create_exec_ctx (GumStalker * self,
                             GumEventSink * sink)
{
  GumExecCtx * ctx;

  ctx = g_new0 (GumExecCtx, 1);

  ctx->stalker = g_object_ref (self);

  gum_code_writer_init (&ctx->code_writer, NULL);
  gum_relocator_init (&ctx->relocator, NULL, &ctx->code_writer);

  ctx->sink = g_object_ref (sink);
  ctx->sink_mask = gum_event_sink_query_mask (sink);
  ctx->sink_process_impl = GUM_EVENT_SINK_GET_INTERFACE (sink)->process;

  gum_exec_ctx_create_thunks (ctx);
  gum_exec_ctx_create_block_pool (ctx);

  g_private_set (self->priv->exec_ctx, ctx);

  return ctx;
}

static void
gum_stalker_destroy_exec_ctx (GumStalker * self,
                              GumExecCtx * ctx)
{
  gum_exec_ctx_destroy_block_pool (ctx);
  gum_exec_ctx_destroy_thunks (ctx);

  g_object_unref (ctx->sink);

  gum_relocator_free (&ctx->relocator);
  gum_code_writer_free (&ctx->code_writer);

  g_object_unref (ctx->stalker);

  g_free (ctx);

  g_private_set (self->priv->exec_ctx, NULL);
}

static GumExecCtx *
gum_stalker_get_exec_ctx (GumStalker * self)
{
  return g_private_get (self->priv->exec_ctx);
}

static gpointer GUM_STDCALL
gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx,
                                         gpointer start_address)
{
  gum_exec_block_free (ctx->current_block);
  ctx->current_block = gum_exec_ctx_create_block_for (ctx, start_address);

  return ctx->current_block->code_begin;
}

static void
gum_exec_ctx_create_thunks (GumExecCtx * ctx)
{
  GumCodeWriter cw;

  g_assert (ctx->thunks == NULL);

  ctx->thunks = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_code_writer_init (&cw, ctx->thunks);

  ctx->jmp_block_thunk = gum_code_writer_cur (&cw);
  gum_code_writer_put_mov_esp_offset_ptr_eax (&cw, CDECL_PRESERVE_SIZE);
  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, &cw);
  gum_code_writer_put_ret (&cw);

  ctx->ret_block_thunk = gum_code_writer_cur (&cw);
  gum_code_writer_put_mov_esp_offset_ptr_eax (&cw,
      sizeof (gpointer) + CDECL_PRESERVE_SIZE);
  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, &cw);
  gum_code_writer_put_ret (&cw);

  ctx->replace_block_thunk = gum_code_writer_cur (&cw);
  gum_code_writer_put_push_eax (&cw); /* placeholder */
  gum_exec_ctx_write_cdecl_preserve_prolog (ctx, &cw);
  gum_code_writer_put_push_imm_ptr (&cw, &ctx->replacement_address);
  gum_code_writer_put_push (&cw, (guint32) ctx);
  gum_code_writer_put_call (&cw, gum_exec_ctx_replace_current_block_with);
  gum_code_writer_put_mov_esp_offset_ptr_eax (&cw, CDECL_PRESERVE_SIZE);
  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, &cw);
  gum_code_writer_put_ret (&cw);

  gum_code_writer_free (&cw);
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

static GumExecBlock *
gum_exec_ctx_create_block_for (GumExecCtx * ctx,
                               gpointer address)
{
  GumExecBlock * block;
  GumCodeWriter * cw = &ctx->code_writer;
  GumRelocator * rl = &ctx->relocator;
  GumGeneratorContext gc;

  block = gum_exec_block_new (ctx);
  gum_code_writer_reset (cw, block->code_begin);
  gum_relocator_reset (rl, address, cw);

  gc.instruction = NULL;
  gc.relocator = rl;
  gc.code_writer = cw;
  gc.continuation_real_address = NULL;

  do
  {
    guint n_read;
    GumInstruction insn;
    GumVirtualizationRequirements requirements = GUM_REQUIRE_NOTHING;

    n_read = gum_relocator_read_one (rl, NULL);
    g_assert_cmpuint (n_read, !=, 0);

    insn.ud = gum_relocator_peek_next_write_insn (rl);
    insn.begin = gum_relocator_peek_next_write_source (rl);
    insn.end = insn.begin + ud_insn_len (insn.ud);

    g_assert (insn.ud != NULL && insn.begin != NULL);

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
        gum_exec_block_add_address_mapping (block, gum_code_writer_cur (cw),
            insn.begin);
      }

      gum_relocator_write_one_no_label (rl);

      if ((requirements & GUM_REQUIRE_MAPPING) != 0)
      {
        gum_exec_block_add_address_mapping (block, gum_code_writer_cur (cw),
            insn.end);
      }
    }
    else if ((requirements & GUM_REQUIRE_SINGLE_STEP) != 0)
    {
      gum_relocator_skip_one_no_label (rl);
      gum_exec_block_write_single_step_transfer_code (block, &gc);
    }

    block->code_end = gum_code_writer_cur (cw);

    if (gum_exec_block_full (block))
    {
      gc.continuation_real_address = insn.end;
      break;
    }
  }
  while (!gum_relocator_eob (rl));

  if (gc.continuation_real_address != NULL)
  {
    GumBranchTarget continue_target = { 0, };

    continue_target.is_indirect = FALSE;
    continue_target.absolute_address = gc.continuation_real_address;

    gum_exec_block_write_jmp_transfer_code (block, &continue_target, cw);
  }

  gum_code_writer_put_int3 (cw); /* should never get here */

  gum_code_writer_flush (cw);

  block->code_end = (guint8 *) gum_code_writer_cur (cw);

  block->real_begin = (guint8 *) rl->input_start;
  block->real_end = (guint8 *) rl->input_cur;

  g_assert_cmpuint (gum_code_writer_offset (cw), <=, ctx->block_code_maxsize);

  block->code_end--; /* pretend the INT3 guard isn't part of the block */

  return block;
}

static void
gum_exec_ctx_write_call_event_code (GumExecCtx * ctx,
                                    gpointer location,
                                    const GumBranchTarget * target,
                                    GumCodeWriter * cw)
{
  gum_exec_ctx_write_cdecl_preserve_prolog (ctx, cw);

  gum_exec_ctx_write_event_init_code (ctx, GUM_CALL, cw);
  gum_code_writer_put_mov_eax_offset_ptr (cw,
      G_STRUCT_OFFSET (GumCallEvent, location), (guint32) location);

  gum_write_push_branch_target_address (target, 0, CDECL_PRESERVE_SIZE, cw);
  gum_code_writer_put_pop_ecx (cw);
  gum_code_writer_put_mov_eax_offset_ptr_ecx (cw,
      G_STRUCT_OFFSET (GumCallEvent, target));

  gum_code_writer_put_mov_ecx_imm_ptr (cw, &ctx->call_depth);
  gum_code_writer_put_mov_eax_offset_ptr_ecx (cw,
      G_STRUCT_OFFSET (GumCallEvent, depth));

  gum_exec_ctx_write_event_submit_code (ctx, cw);

  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, cw);
}

static void
gum_exec_ctx_write_ret_event_code (GumExecCtx * ctx,
                                   gpointer location,
                                   GumCodeWriter * cw)
{
  gum_exec_ctx_write_cdecl_preserve_prolog (ctx, cw);

  gum_code_writer_put_mov_ecx_esp_offset_ptr (cw, CDECL_PRESERVE_SIZE);
  gum_code_writer_put_push_ecx (cw);
  gum_code_writer_put_push (cw, (guint32) ctx);
  gum_code_writer_put_call (cw, gum_exec_ctx_resolve_code_address);
  gum_code_writer_put_add_esp_u32 (cw, 2 * sizeof (gpointer));
  gum_code_writer_put_mov_ecx_eax (cw);

  gum_exec_ctx_write_event_init_code (ctx, GUM_RET, cw);
  gum_code_writer_put_mov_eax_offset_ptr (cw,
      G_STRUCT_OFFSET (GumRetEvent, location), (guint32) location);

  gum_code_writer_put_mov_eax_offset_ptr_ecx (cw,
      G_STRUCT_OFFSET (GumRetEvent, target));

  gum_code_writer_put_mov_ecx_imm_ptr (cw, &ctx->call_depth);
  gum_code_writer_put_mov_eax_offset_ptr_ecx (cw,
      G_STRUCT_OFFSET (GumCallEvent, depth));

  gum_exec_ctx_write_event_submit_code (ctx, cw);

  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, cw);
}

static void
gum_exec_ctx_write_exec_event_code (GumExecCtx * ctx,
                                    gpointer location,
                                    GumCodeWriter * cw)
{
  gum_exec_ctx_write_cdecl_preserve_prolog (ctx, cw);

  gum_exec_ctx_write_event_init_code (ctx, GUM_EXEC, cw);
  gum_code_writer_put_mov_eax_offset_ptr (cw,
      G_STRUCT_OFFSET (GumExecEvent, location), (guint32) location);

  gum_exec_ctx_write_event_submit_code (ctx, cw);

  gum_exec_ctx_write_cdecl_preserve_epilog (ctx, cw);
}

static void
gum_exec_ctx_write_event_init_code (GumExecCtx * ctx,
                                    GumEventType type,
                                    GumCodeWriter * cw)
{
  gum_code_writer_put_mov_eax (cw, (guint32) &ctx->tmp_event);
  gum_code_writer_put_mov_eax_offset_ptr (cw,
      G_STRUCT_OFFSET (GumAnyEvent, type), type);
}

static void
gum_exec_ctx_write_event_submit_code (GumExecCtx * ctx,
                                      GumCodeWriter * cw)
{
  gum_code_writer_put_push_eax (cw);
  gum_code_writer_put_push (cw, (guint32) ctx->sink);
  gum_code_writer_put_call (cw, ctx->sink_process_impl);
  gum_code_writer_put_add_esp_u32 (cw, 2 * sizeof (gpointer));
}

static void
gum_exec_ctx_write_cdecl_preserve_prolog (GumExecCtx * ctx,
                                          GumCodeWriter * cw)
{
  gum_code_writer_put_pushfd (cw);
  gum_code_writer_put_push_eax (cw);
  gum_code_writer_put_push_ecx (cw);
  gum_code_writer_put_push_edx (cw);
}

static void
gum_exec_ctx_write_cdecl_preserve_epilog (GumExecCtx * ctx,
                                          GumCodeWriter * cw)
{
  gum_code_writer_put_pop_edx (cw);
  gum_code_writer_put_pop_ecx (cw);
  gum_code_writer_put_pop_eax (cw);
  gum_code_writer_put_popfd (cw);
}

static void
gum_exec_ctx_write_depth_increment_code (GumExecCtx * ctx,
    GumCodeWriter * cw)
{
  static const guint8 templ[2] = { 0xff, 0x05 };
  gpointer ptr = &ctx->call_depth;

  gum_code_writer_put_pushfd (cw);
  gum_code_writer_put_bytes (cw, templ, sizeof (templ));
  gum_code_writer_put_bytes (cw, (guint8 *) &ptr, sizeof (ptr));
  gum_code_writer_put_popfd (cw);
}

static void
gum_exec_ctx_write_depth_decrement_code (GumExecCtx * ctx,
    GumCodeWriter * cw)
{
  static const guint8 templ[2] = { 0xff, 0x0d };
  gpointer ptr = &ctx->call_depth;

  gum_code_writer_put_pushfd (cw);
  gum_code_writer_put_bytes (cw, templ, sizeof (templ));
  gum_code_writer_put_bytes (cw, (guint8 *) &ptr, sizeof (ptr));
  gum_code_writer_put_popfd (cw);
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
  GumCodeWriter * cw = gc->code_writer;
  gboolean is_conditional;
  ud_operand_t * op = &insn->ud->operand[0];
  GumBranchTarget target = { 0, };

  is_conditional =
      (insn->ud->mnemonic != UD_Icall && insn->ud->mnemonic != UD_Ijmp);

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
    g_assert (op->size == 32);
    g_assert (op->base == UD_NONE ||
        (op->base >= UD_R_EAX && op->base <= UD_R_EDI));
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

  if (target.absolute_address == gum_stalker_unfollow_me)
    return GUM_REQUIRE_RELOCATION | GUM_REQUIRE_MAPPING;

  gum_relocator_skip_one_no_label (gc->relocator);

  if (insn->ud->mnemonic == UD_Icall)
  {
    if ((block->ctx->sink_mask & GUM_CALL) != 0)
      gum_exec_ctx_write_call_event_code (block->ctx, insn->begin, &target, cw);
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

      gum_code_writer_put_jcc_short_label (cw,
          gum_jcc_opcode_negate (gum_jcc_insn_to_short_opcode (insn->begin)),
          cond_false_lbl_id);
    }

    gum_exec_block_write_jmp_transfer_code (block, &target, cw);

    if (is_conditional)
    {
      GumBranchTarget cond_target = { 0, };

      cond_target.is_indirect = FALSE;
      cond_target.absolute_address = insn->end;

      gum_code_writer_put_label (cw, cond_false_lbl_id);
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

    insn_start = gum_relocator_peek_next_write_source (gc->relocator);

    gum_exec_ctx_write_ret_event_code (block->ctx, insn_start,
        gc->code_writer);
  }

  gum_relocator_skip_one_no_label (gc->relocator);

  if ((block->ctx->sink_mask & (GUM_CALL | GUM_RET)) != 0)
    gum_exec_ctx_write_depth_decrement_code (block->ctx, gc->code_writer);

  gum_exec_block_write_ret_transfer_code (block, gc->instruction->begin,
      gc->code_writer);

  return GUM_REQUIRE_NOTHING;
}

static void
gum_exec_block_write_call_invoke_code (GumExecBlock * block,
                                       GumInstruction * insn,
                                       const GumBranchTarget * target,
                                       GumCodeWriter * cw)
{
  /* untouched return-address */
  gum_code_writer_put_push (cw, GPOINTER_TO_SIZE (insn->end));

  gum_code_writer_put_push_eax (cw); /* placeholder */
  gum_exec_ctx_write_cdecl_preserve_prolog (block->ctx, cw);

  gum_write_push_branch_target_address (target, 0, CDECL_PRESERVE_SIZE + 8,
      cw);
  gum_code_writer_put_push (cw, (guint32) block->ctx);

  gum_code_writer_put_push (cw, (guint32) block->ctx->jmp_block_thunk);
  gum_code_writer_put_jmp (cw, gum_exec_ctx_replace_current_block_with);
}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        GumCodeWriter * cw)
{
  gum_code_writer_put_push_eax (cw); /* placeholder */
  gum_exec_ctx_write_cdecl_preserve_prolog (block->ctx, cw);

  gum_write_push_branch_target_address (target, 0, CDECL_PRESERVE_SIZE + 4,
      cw);
  gum_code_writer_put_push (cw, (guint32) block->ctx);

  gum_code_writer_put_push (cw, (guint32) block->ctx->jmp_block_thunk);
  gum_code_writer_put_jmp (cw, gum_exec_ctx_replace_current_block_with);
}

static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        gpointer orig_ret_insn,
                                        GumCodeWriter * cw)
{
  gum_code_writer_put_push (cw, (guint32) orig_ret_insn);
  gum_exec_ctx_write_cdecl_preserve_prolog (block->ctx, cw);

  gum_code_writer_put_mov_ecx_esp_offset_ptr (cw,
      CDECL_PRESERVE_SIZE + sizeof (gpointer));
  gum_code_writer_put_push_ecx (cw);
  gum_code_writer_put_push (cw, (guint32) block->ctx);

  gum_code_writer_put_push (cw, (guint32) block->ctx->ret_block_thunk);
  gum_code_writer_put_jmp (cw, gum_exec_ctx_replace_current_block_with);
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
  gum_code_writer_put_bytes (gc->code_writer, code, sizeof (code));
  gum_code_writer_put_jmp (gc->code_writer, gc->instruction->begin);
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

static gpointer
gum_exec_block_get_real_address_of_last_instruction (GumExecBlock * block)
{
  return block->mappings[block->mappings_len - 1].real_address;
}

static void
gum_write_push_branch_target_address (const GumBranchTarget * target,
                                      guint cdecl_preserve_stack_offset,
                                      guint accumulated_stack_delta,
                                      GumCodeWriter * cw)
{
  if (!target->is_indirect)
  {
    if (target->base == UD_NONE)
    {
      gum_code_writer_put_push (cw, (guint32) target->absolute_address);
    }
    else
    {
      guint8 xchg_eax_esp_template[] = { 0x87, 0x04, 0x24 };

      gum_code_writer_put_push_eax (cw);
      gum_load_real_register_into (UD_R_EAX, target->base,
          cdecl_preserve_stack_offset + 4, accumulated_stack_delta + 4, cw);
      gum_code_writer_put_bytes (cw, xchg_eax_esp_template,
          sizeof (xchg_eax_esp_template));
    }
  }
  else if (target->base == UD_NONE && target->index == UD_NONE)
  {
    g_assert (target->scale == 0);
    g_assert (target->absolute_address != NULL);
    g_assert (target->relative_offset == 0);

    gum_write_segment_prefix (target->pfx_seg, cw);
    gum_code_writer_put_byte (cw, 0xff);
    gum_code_writer_put_byte (cw, 0x35);
    gum_code_writer_put_bytes (cw, (guint8 *) &target->absolute_address,
        sizeof (target->absolute_address));
  }
  else
  {
    gum_code_writer_put_push_eax (cw); /* placeholder */

    gum_code_writer_put_push_eax (cw);
    gum_code_writer_put_push_edx (cw);

    gum_load_real_register_into (UD_R_EAX, target->base,
        cdecl_preserve_stack_offset + 12, accumulated_stack_delta + 12, cw);
    gum_load_real_register_into (UD_R_EDX, target->index,
        cdecl_preserve_stack_offset + 12, accumulated_stack_delta + 12, cw);

    {
      const guint8 scale_lookup[] = {
          0x00,
          0x00,
          0x40,
          0xff,
          0x80,
          0xff,
          0xff,
          0xff,
          0xc0
      };
      guint8 mov_reg_scale_imm_template[] = { 0x8b, 0x84, 0x10 };

      mov_reg_scale_imm_template[2] += scale_lookup[target->scale];
      gum_write_segment_prefix (target->pfx_seg, cw);
      gum_code_writer_put_bytes (cw, mov_reg_scale_imm_template,
          sizeof (mov_reg_scale_imm_template));
      gum_code_writer_put_bytes (cw, (guint8 *) &target->relative_offset,
          sizeof (target->relative_offset));
    }

    gum_code_writer_put_mov_esp_offset_ptr_eax (cw, 8);

    gum_code_writer_put_pop_edx (cw);
    gum_code_writer_put_pop_eax (cw);
  }
}

static void
gum_load_real_register_into (enum ud_type target_register,
                             enum ud_type source_register,
                             guint8 cdecl_preserve_stack_offset,
                             guint accumulated_stack_delta,
                             GumCodeWriter * cw)
{
  if (source_register >= UD_R_EAX && source_register <= UD_R_EDX)
  {
    guint8 mov_from_stack_template[] = { 0x8b, 0x44, 0x24 };

    mov_from_stack_template[1] += (target_register - UD_R_EAX) << 3;
    gum_code_writer_put_bytes (cw, mov_from_stack_template,
        sizeof (mov_from_stack_template));
    gum_code_writer_put_byte (cw, cdecl_preserve_stack_offset + 8 -
        ((source_register - UD_R_EAX) * 4));
  }
  else if (source_register == UD_R_ESP)
  {
    guint8 lea_template[] = { 0x8d, 0x84, 0x24 };

    lea_template[1] += (target_register - UD_R_EAX) << 3;
    gum_code_writer_put_bytes (cw, lea_template, sizeof (lea_template));
    gum_code_writer_put_bytes (cw, (guint8 *) &accumulated_stack_delta,
        sizeof (accumulated_stack_delta));
  }
  else if (source_register == UD_NONE)
  {
    guint8 xor_reg_reg_template[] = { 0x31, 0xc0 };

    xor_reg_reg_template[1] |= (target_register - UD_R_EAX) << 3;
    xor_reg_reg_template[1] |=  target_register - UD_R_EAX;

    gum_code_writer_put_bytes (cw, xor_reg_reg_template,
        sizeof (xor_reg_reg_template));
  }
  else
  {
    guint8 mov_reg_reg_template[] = { 0x89, 0xc0 };

    mov_reg_reg_template[1] |= (source_register - UD_R_EAX) << 3;
    mov_reg_reg_template[1] |=  target_register - UD_R_EAX;

    gum_code_writer_put_bytes (cw, mov_reg_reg_template,
        sizeof (mov_reg_reg_template));
  }
}

static void
gum_write_segment_prefix (uint8_t segment,
                          GumCodeWriter * cw)
{
  switch (segment)
  {
    case UD_NONE: break;

    case UD_R_CS: gum_code_writer_put_byte (cw, 0x2e); break;
    case UD_R_SS: gum_code_writer_put_byte (cw, 0x36); break;
    case UD_R_DS: gum_code_writer_put_byte (cw, 0x3e); break;
    case UD_R_ES: gum_code_writer_put_byte (cw, 0x26); break;
    case UD_R_FS: gum_code_writer_put_byte (cw, 0x64); break;
    case UD_R_GS: gum_code_writer_put_byte (cw, 0x65); break;

    default:
      g_assert_not_reached ();
      break;
  }
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
  GumStalker * self = GUM_STALKER (user_data);
  GumExecCtx * ctx;
  GumExecBlock * block;

  if (exception_record->ExceptionCode != STATUS_SINGLE_STEP)
    return FALSE;

  ctx = gum_stalker_get_exec_ctx (self);
  if (ctx == NULL)
    return FALSE;

  block = ctx->current_block;

#ifdef _M_IX86
  /*
  printf ("gum_stalker_handle_exception state=%u %p %08x\n",
      block->state, context->Eip, exception_record->ExceptionCode);
  */

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
#endif

  return TRUE;
}

#endif
