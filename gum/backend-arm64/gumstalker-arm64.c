/*
 * Copyright (C) 2014-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 * Copyright (C) 2019 John Coates <john@johncoates.dev>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumstalker.h"

#include "gumarm64reader.h"
#include "gumarm64relocator.h"
#include "gumarm64writer.h"
#include "gumexceptor.h"
#include "gummemory.h"
#include "gummetalhash.h"
#include "gumspinlock.h"
#include "gumtls.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define GUM_CODE_SLAB_SIZE_INITIAL  (128 * 1024)
#define GUM_CODE_SLAB_SIZE_DYNAMIC  (4 * 1024 * 1024)
#define GUM_DATA_SLAB_SIZE_INITIAL  (GUM_CODE_SLAB_SIZE_INITIAL / 5)
#define GUM_DATA_SLAB_SIZE_DYNAMIC  (GUM_CODE_SLAB_SIZE_DYNAMIC / 5)
#define GUM_SCRATCH_SLAB_SIZE       16384
#define GUM_EXEC_BLOCK_MIN_CAPACITY 1024

#define GUM_STACK_ALIGNMENT                16
#define GUM_INVALIDATE_TRAMPOLINE_MAX_SIZE 24
#define GUM_RESTORATION_PROLOG_SIZE        4

#define GUM_INSTRUCTION_OFFSET_NONE (-1)

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;
typedef struct _GumActivation GumActivation;
typedef struct _GumInvalidateContext GumInvalidateContext;
typedef struct _GumCallProbe GumCallProbe;

typedef struct _GumExecCtx GumExecCtx;
typedef void (* GumExecHelperWriteFunc) (GumExecCtx * ctx, GumArm64Writer * cw);
typedef gpointer (GUM_THUNK * GumExecCtxReplaceCurrentBlockFunc) (
    GumExecCtx * ctx, gpointer start_address);

typedef struct _GumExecBlock GumExecBlock;
typedef guint GumExecBlockFlags;

typedef struct _GumExecFrame GumExecFrame;

typedef struct _GumCodeSlab GumCodeSlab;
typedef struct _GumDataSlab GumDataSlab;
typedef struct _GumSlab GumSlab;

typedef guint GumPrologType;
typedef guint GumCodeContext;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumCalloutEntry GumCalloutEntry;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;

typedef guint GumVirtualizationRequirements;

struct _GumStalker
{
  GObject parent;

  gsize ctx_size;
  gsize ctx_header_size;

  goffset frames_offset;
  gsize frames_size;

  goffset thunks_offset;
  gsize thunks_size;

  goffset code_slab_offset;
  gsize code_slab_size_initial;
  gsize code_slab_size_dynamic;

  goffset data_slab_offset;
  gsize data_slab_size_initial;
  gsize data_slab_size_dynamic;

  goffset scratch_slab_offset;
  gsize scratch_slab_size;

  gsize page_size;
  GumCpuFeatures cpu_features;
  gboolean is_rwx_supported;

  GMutex mutex;
  GSList * contexts;
  GumTlsKey exec_ctx;

  GArray * exclusions;
  gint trust_threshold;
  volatile gboolean any_probes_attached;
  volatile gint last_probe_id;
  GumSpinlock probe_lock;
  GHashTable * probe_target_by_id;
  GHashTable * probe_array_by_address;

  GumExceptor * exceptor;
};

struct _GumInfectContext
{
  GumStalker * stalker;
  GumStalkerTransformer * transformer;
  GumEventSink * sink;
};

struct _GumDisinfectContext
{
  GumExecCtx * exec_ctx;
  gboolean success;
};

struct _GumActivation
{
  GumExecCtx * ctx;
  gboolean pending;
  gconstpointer target;
};

struct _GumInvalidateContext
{
  GumExecBlock * block;
  gboolean is_executing_target_block;
};

struct _GumCallProbe
{
  gint ref_count;
  GumProbeId id;
  GumCallProbeCallback callback;
  gpointer user_data;
  GDestroyNotify user_notify;
};

struct _GumExecCtx
{
  volatile gint state;
  gint64 destroy_pending_since;

  GumStalker * stalker;
  GumThreadId thread_id;

  GumArm64Writer code_writer;
  GumArm64Relocator relocator;

  GumStalkerTransformer * transformer;
  void (* transform_block_impl) (GumStalkerTransformer * self,
      GumStalkerIterator * iterator, GumStalkerOutput * output);
  GumEventSink * sink;
  gboolean sink_started;
  GumEventType sink_mask;
  void (* sink_process_impl) (GumEventSink * self, const GumEvent * event,
      GumCpuContext * cpu_context);
  GumStalkerObserver * observer;

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;
  gpointer pending_return_location;
  guint pending_calls;
  guint pending_stack_misalignment;
  GumExecFrame * current_frame;
  GumExecFrame * first_frame;
  GumExecFrame * frames;

  gpointer resume_at;
  gpointer return_at;
  gconstpointer activation_target;

  gpointer thunks;
  gpointer infect_thunk;
  GumAddress infect_body;

  GumSpinlock code_lock;
  GumCodeSlab * code_slab;
  GumDataSlab * data_slab;
  GumCodeSlab * scratch_slab;
  GumMetalHashTable * mappings;
  gpointer last_prolog_minimal;
  gpointer last_epilog_minimal;
  gpointer last_prolog_full;
  gpointer last_epilog_full;
  gpointer last_stack_push;
  gpointer last_stack_pop_and_go;
  gpointer last_invalidator;
};

enum _GumExecCtxState
{
  GUM_EXEC_CTX_ACTIVE,
  GUM_EXEC_CTX_UNFOLLOW_PENDING,
  GUM_EXEC_CTX_DESTROY_PENDING
};

struct _GumExecBlock
{
  GumExecCtx * ctx;
  GumCodeSlab * code_slab;
  GumExecBlock * storage_block;

  guint8 * real_start;
  guint8 * code_start;
  guint real_size;
  guint code_size;
  guint capacity;
  guint last_callout_offset;

  GumExecBlockFlags flags;
  gint recycle_count;
};

enum _GumExecBlockFlags
{
  GUM_EXEC_BLOCK_ACTIVATION_TARGET = 1 << 0,
};

struct _GumExecFrame
{
  gpointer real_address;
  gpointer code_address;
};

struct _GumSlab
{
  guint8 * data;
  guint offset;
  guint size;
  GumSlab * next;
};

struct _GumCodeSlab
{
  GumSlab slab;

  gpointer invalidator;
};

struct _GumDataSlab
{
  GumSlab slab;
};

enum _GumPrologType
{
  GUM_PROLOG_NONE,
  GUM_PROLOG_MINIMAL,
  GUM_PROLOG_FULL
};

enum _GumCodeContext
{
  GUM_CODE_INTERRUPTIBLE,
  GUM_CODE_UNINTERRUPTIBLE
};

struct _GumGeneratorContext
{
  GumInstruction * instruction;
  GumArm64Relocator * relocator;
  GumArm64Writer * code_writer;
  gpointer continuation_real_address;
  GumPrologType opened_prolog;
  gint exclusive_load_offset;
};

struct _GumInstruction
{
  const cs_insn * ci;
  guint8 * start;
  guint8 * end;
};

struct _GumStalkerIterator
{
  GumExecCtx * exec_context;
  GumExecBlock * exec_block;
  GumGeneratorContext * generator_context;

  GumInstruction instruction;
  GumVirtualizationRequirements requirements;
};

struct _GumCalloutEntry
{
  GumStalkerCallout callout;
  gpointer data;
  GDestroyNotify data_destroy;

  gpointer pc;

  GumExecCtx * exec_context;

  GumCalloutEntry * next;
};

struct _GumBranchTarget
{
  gpointer origin_ip;

  gpointer absolute_address;
  gssize relative_offset;

  arm64_reg reg;
};

enum _GumVirtualizationRequirements
{
  GUM_REQUIRE_NOTHING          = 0,
  GUM_REQUIRE_RELOCATION       = 1 << 0,
  GUM_REQUIRE_EXCLUSIVE_STORE  = 1 << 1,
};

static void gum_stalker_dispose (GObject * object);
static void gum_stalker_finalize (GObject * object);

G_GNUC_INTERNAL gpointer _gum_stalker_do_follow_me (GumStalker * self,
    GumStalkerTransformer * transformer, GumEventSink * sink,
    gpointer ret_addr);
static void gum_stalker_infect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
static void gum_stalker_disinfect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
G_GNUC_INTERNAL gpointer _gum_stalker_do_activate (GumStalker * self,
    gconstpointer target, gpointer ret_addr);
G_GNUC_INTERNAL gpointer _gum_stalker_do_deactivate (GumStalker * self,
    gpointer ret_addr);
static gboolean gum_stalker_do_invalidate (GumExecCtx * ctx,
    gconstpointer address, GumActivation * activation);
static void gum_stalker_try_invalidate_block_owned_by_thread (
    GumThreadId thread_id, GumCpuContext * cpu_context, gpointer user_data);

static GumCallProbe * gum_call_probe_ref (GumCallProbe * probe);
static void gum_call_probe_unref (GumCallProbe * probe);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumThreadId thread_id, GumStalkerTransformer * transformer,
    GumEventSink * sink);
static void gum_stalker_destroy_exec_ctx (GumStalker * self, GumExecCtx * ctx);
static GumExecCtx * gum_stalker_get_exec_ctx (GumStalker * self);
static GumExecCtx * gum_stalker_find_exec_ctx_by_thread_id (GumStalker * self,
    GumThreadId thread_id);

static gsize gum_stalker_snapshot_space_needed_for (GumStalker * self,
    gsize real_size);

static void gum_stalker_thaw (GumStalker * self, gpointer code, gsize size);
static void gum_stalker_freeze (GumStalker * self, gpointer code, gsize size);

static gboolean gum_stalker_on_exception (GumExceptionDetails * details,
    gpointer user_data);

static GumExecCtx * gum_exec_ctx_new (GumStalker * self, GumThreadId thread_id,
    GumStalkerTransformer * transformer, GumEventSink * sink);
static void gum_exec_ctx_free (GumExecCtx * ctx);
static void gum_exec_ctx_dispose (GumExecCtx * ctx);
static GumCodeSlab * gum_exec_ctx_add_code_slab (GumExecCtx * ctx,
    GumCodeSlab * code_slab);
static GumDataSlab * gum_exec_ctx_add_data_slab (GumExecCtx * ctx,
    GumDataSlab * data_slab);
static void gum_exec_ctx_compute_code_address_spec (GumExecCtx * ctx,
    gsize slab_size, GumAddressSpec * spec);
static void gum_exec_ctx_compute_data_address_spec (GumExecCtx * ctx,
    gsize slab_size, GumAddressSpec * spec);
static gboolean gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
    gpointer resume_at);
static void gum_exec_ctx_unfollow (GumExecCtx * ctx, gpointer resume_at);
static gboolean gum_exec_ctx_has_executed (GumExecCtx * ctx);
static gboolean gum_exec_ctx_contains (GumExecCtx * ctx, gconstpointer address);
static gpointer gum_exec_ctx_switch_block (GumExecCtx * ctx,
    gpointer start_address);
static void gum_exec_ctx_begin_call (GumExecCtx * ctx, gpointer ret_addr);
static void gum_exec_ctx_end_call (GumExecCtx * ctx);

static GumExecBlock * gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address);
static void gum_exec_ctx_recompile_block (GumExecCtx * ctx,
    GumExecBlock * block);
static void gum_exec_ctx_compile_block (GumExecCtx * ctx, GumExecBlock * block,
    gconstpointer input_code, gpointer output_code, GumAddress output_pc,
    guint * input_size, guint * output_size);
static void gum_exec_ctx_maybe_emit_compile_event (GumExecCtx * ctx,
    GumExecBlock * block);

static gboolean gum_stalker_iterator_is_out_of_space (
    GumStalkerIterator * self);

static void gum_stalker_invoke_callout (GumCalloutEntry * entry,
    GumCpuContext * cpu_context);

static void gum_exec_ctx_write_prolog (GumExecCtx * ctx, GumPrologType type,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_epilog (GumExecCtx * ctx, GumPrologType type,
    GumArm64Writer * cw);

static void gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx);
static void gum_exec_ctx_write_minimal_prolog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_minimal_epilog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_full_prolog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_full_epilog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
    GumPrologType type, GumArm64Writer * cw);
static void gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
    GumPrologType type, GumArm64Writer * cw);
static void gum_exec_ctx_write_stack_push_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_stack_pop_and_go_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_invalidator (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_ensure_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr, GumExecHelperWriteFunc write);
static gboolean gum_exec_ctx_is_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr);

static void gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
    arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx, arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_from_full_frame_into (
    GumExecCtx * ctx, arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc);

static gboolean gum_exec_ctx_try_handle_exception (GumExecCtx * ctx,
    GumExceptionDetails * details);
static gboolean gum_exec_ctx_try_handle_misaligned_stack_in_prolog (
    GumExecCtx * ctx, GumCpuContext * cpu_context);
static gboolean gum_exec_ctx_try_handle_misaligned_stack_in_epilog (
    GumExecCtx * ctx, GumCpuContext * cpu_context);
static gboolean gum_exec_ctx_try_handle_misaligned_stack_in_transition (
    GumExecCtx * ctx, GumCpuContext * cpu_context);
static void gum_exec_ctx_handle_misaligned_stack_in_exec_generated_code (
    GumExecCtx * ctx, GumCpuContext * cpu_context);
static void gum_exec_ctx_handle_misaligned_stack_in_jmp_transfer_ic (
    GumExecCtx * ctx, GumCpuContext * cpu_context);
static void gum_exec_ctx_handle_misaligned_stack_in_call_invoke_ic (
    GumExecCtx * ctx, GumCpuContext * cpu_context);
static void gum_exec_ctx_handle_misaligned_stack_in_ret_transfer_code (
    GumExecCtx * ctx, GumCpuContext * cpu_context,
    const guint32 * mov_instruction);
static void gum_exec_ctx_align_stack_temporarily (GumExecCtx * ctx,
    GumCpuContext * cpu_context);
static void gum_exec_ctx_undo_temporary_stack_alignment (GumExecCtx * ctx,
    GumCpuContext * cpu_context);
static void gum_exec_ctx_set_program_counter_to_naked_resume_address (
    GumExecCtx * ctx, GumCpuContext * cpu_context);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static void gum_exec_block_clear (GumExecBlock * block);
static gconstpointer gum_exec_block_check_address_for_exclusion (
    GumExecBlock * block, gconstpointer address);
static void gum_exec_block_commit (GumExecBlock * block);
static void gum_exec_block_invalidate (GumExecBlock * block);
static gpointer gum_exec_block_get_snapshot_start (GumExecBlock * block);
static GumCalloutEntry * gum_exec_block_get_last_callout_entry (
    const GumExecBlock * block);
static void gum_exec_block_set_last_callout_entry (GumExecBlock * block,
    GumCalloutEntry * entry);

static GumVirtualizationRequirements gum_exec_block_virtualize_branch_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_ret_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_sysenter_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
#ifdef HAVE_LINUX
static GumVirtualizationRequirements gum_exec_block_virtualize_linux_sysenter (
    GumExecBlock * block, GumGeneratorContext * gc);
#endif

static void gum_exec_block_write_call_invoke_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
    const GumBranchTarget * target, GumExecCtxReplaceCurrentBlockFunc func,
    GumGeneratorContext * gc);
static void gum_exec_block_write_jmp_to_block_start (GumExecBlock * block,
    gpointer block_start);
static void gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
    GumGeneratorContext * gc, arm64_reg ret_reg);

static void gum_exec_block_write_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc,
    GumCodeContext cc);
static void gum_exec_block_write_ret_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);

static void gum_exec_block_maybe_write_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_invoke_call_probes (GumExecBlock * block,
    GumCpuContext * cpu_context);

static void gum_exec_block_write_exec_generated_code (GumArm64Writer * cw,
    GumExecCtx * ctx);

static gpointer gum_exec_block_write_inline_data (GumArm64Writer * cw,
    gconstpointer data, gsize size, GumAddress * address);

static void gum_exec_block_open_prolog (GumExecBlock * block,
    GumPrologType type, GumGeneratorContext * gc);
static void gum_exec_block_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);

static GumCodeSlab * gum_code_slab_new (GumExecCtx * ctx);
static void gum_code_slab_free (GumCodeSlab * code_slab);
static void gum_code_slab_init (GumCodeSlab * code_slab, gsize slab_size,
    gsize page_size);

static GumDataSlab * gum_data_slab_new (GumExecCtx * ctx);
static void gum_data_slab_free (GumDataSlab * data_slab);
static void gum_data_slab_init (GumDataSlab * data_slab, gsize slab_size);

static void gum_scratch_slab_init (GumCodeSlab * scratch_slab, gsize slab_size);

static void gum_slab_free (GumSlab * slab);
static void gum_slab_init (GumSlab * slab, gsize slab_size, gsize header_size);
static gsize gum_slab_available (GumSlab * self);
static gpointer gum_slab_start (GumSlab * self);
static gpointer gum_slab_end (GumSlab * self);
static gpointer gum_slab_cursor (GumSlab * self);
static gpointer gum_slab_reserve (GumSlab * self, gsize size);
static gpointer gum_slab_try_reserve (GumSlab * self, gsize size);

static gpointer gum_find_thread_exit_implementation (void);

static gboolean gum_is_mov_reg_reg (guint32 insn);
static gboolean gum_is_mov_x16_reg (guint32 insn);
static gboolean gum_is_ldr_x16_pcrel (guint32 insn);
static gboolean gum_is_b_imm (guint32 insn);
G_GNUC_UNUSED static gboolean gum_is_bl_imm (guint32 insn);

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT)

static gpointer gum_unfollow_me_address;
static gpointer gum_deactivate_address;
static gpointer gum_thread_exit_address;

gboolean
gum_stalker_is_supported (void)
{
  return TRUE;
}

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_stalker_dispose;
  object_class->finalize = gum_stalker_finalize;

  gum_unfollow_me_address = gum_strip_code_pointer (gum_stalker_unfollow_me);
  gum_deactivate_address = gum_strip_code_pointer (gum_stalker_deactivate);
  gum_thread_exit_address = gum_find_thread_exit_implementation ();
}

static void
gum_stalker_init (GumStalker * self)
{
  gsize page_size;

  self->exclusions = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
  self->trust_threshold = 1;

  gum_spinlock_init (&self->probe_lock);
  self->probe_target_by_id = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  self->probe_array_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) g_ptr_array_unref);

  page_size = gum_query_page_size ();

  self->frames_size = page_size;
  g_assert (self->frames_size % sizeof (GumExecFrame) == 0);
  self->thunks_size = page_size;
  self->code_slab_size_initial =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_SIZE_INITIAL, page_size);
  self->data_slab_size_initial =
      GUM_ALIGN_SIZE (GUM_DATA_SLAB_SIZE_INITIAL, page_size);
  self->code_slab_size_dynamic =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_SIZE_DYNAMIC, page_size);
  self->data_slab_size_dynamic =
      GUM_ALIGN_SIZE (GUM_DATA_SLAB_SIZE_DYNAMIC, page_size);
  self->scratch_slab_size = GUM_ALIGN_SIZE (GUM_SCRATCH_SLAB_SIZE, page_size);
  self->ctx_header_size = GUM_ALIGN_SIZE (sizeof (GumExecCtx), page_size);
  self->ctx_size =
      self->ctx_header_size +
      self->frames_size +
      self->thunks_size +
      self->code_slab_size_initial +
      self->data_slab_size_initial +
      self->scratch_slab_size +
      0;

  self->frames_offset = self->ctx_header_size;
  self->thunks_offset = self->frames_offset + self->frames_size;
  self->code_slab_offset = self->thunks_offset + self->thunks_size;
  self->data_slab_offset =
      self->code_slab_offset + self->code_slab_size_initial;
  self->scratch_slab_offset =
      self->data_slab_offset + self->data_slab_size_initial;

  self->page_size = page_size;
  self->cpu_features = gum_query_cpu_features ();
  self->is_rwx_supported = gum_query_rwx_support () != GUM_RWX_NONE;

  g_mutex_init (&self->mutex);
  self->contexts = NULL;
  self->exec_ctx = gum_tls_key_new ();

  self->exceptor = gum_exceptor_obtain ();
  gum_exceptor_add (self->exceptor, gum_stalker_on_exception, self);
}

static void
gum_stalker_dispose (GObject * object)
{
  GumStalker * self = GUM_STALKER (object);

  if (self->exceptor != NULL)
  {
    gum_exceptor_remove (self->exceptor, gum_stalker_on_exception, self);
    g_object_unref (self->exceptor);
    self->exceptor = NULL;
  }

  G_OBJECT_CLASS (gum_stalker_parent_class)->dispose (object);
}

static void
gum_stalker_finalize (GObject * object)
{
  GumStalker * self = GUM_STALKER (object);

  g_hash_table_unref (self->probe_array_by_address);
  g_hash_table_unref (self->probe_target_by_id);

  g_array_free (self->exclusions, TRUE);

  g_assert (self->contexts == NULL);
  gum_tls_key_free (self->exec_ctx);
  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_stalker_parent_class)->finalize (object);
}

GumStalker *
gum_stalker_new (void)
{
  return g_object_new (GUM_TYPE_STALKER, NULL);
}

void
gum_stalker_exclude (GumStalker * self,
                     const GumMemoryRange * range)
{
  g_array_append_val (self->exclusions, *range);
}

static gboolean
gum_stalker_is_excluding (GumStalker * self,
                          gconstpointer address)
{
  GArray * exclusions = self->exclusions;
  guint i;

  for (i = 0; i != exclusions->len; i++)
  {
    GumMemoryRange * r = &g_array_index (exclusions, GumMemoryRange, i);

    if (GUM_MEMORY_RANGE_INCLUDES (r, GUM_ADDRESS (address)))
      return TRUE;
  }

  return FALSE;
}

gint
gum_stalker_get_trust_threshold (GumStalker * self)
{
  return self->trust_threshold;
}

void
gum_stalker_set_trust_threshold (GumStalker * self,
                                 gint trust_threshold)
{
  self->trust_threshold = trust_threshold;
}

void
gum_stalker_flush (GumStalker * self)
{
  GSList * sinks, * cur;

  GUM_STALKER_LOCK (self);

  sinks = NULL;
  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = cur->data;

    sinks = g_slist_prepend (sinks, g_object_ref (ctx->sink));
  }

  GUM_STALKER_UNLOCK (self);

  for (cur = sinks; cur != NULL; cur = cur->next)
  {
    GumEventSink * sink = cur->data;

    gum_event_sink_flush (sink);
  }

  g_slist_free_full (sinks, g_object_unref);
}

void
gum_stalker_stop (GumStalker * self)
{
  GSList * cur;

  gum_spinlock_acquire (&self->probe_lock);
  g_hash_table_remove_all (self->probe_target_by_id);
  g_hash_table_remove_all (self->probe_array_by_address);
  self->any_probes_attached = FALSE;
  gum_spinlock_release (&self->probe_lock);

rescan:
  GUM_STALKER_LOCK (self);

  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = cur->data;

    if (g_atomic_int_get (&ctx->state) == GUM_EXEC_CTX_ACTIVE)
    {
      GumThreadId thread_id = ctx->thread_id;

      GUM_STALKER_UNLOCK (self);

      gum_stalker_unfollow (self, thread_id);

      goto rescan;
    }
  }

  GUM_STALKER_UNLOCK (self);

  gum_stalker_garbage_collect (self);
}

gboolean
gum_stalker_garbage_collect (GumStalker * self)
{
  gboolean have_pending_garbage;
  GumThreadId current_thread_id;
  gint64 now;
  GSList * cur;

  current_thread_id = gum_process_get_current_thread_id ();
  now = g_get_monotonic_time ();

rescan:
  GUM_STALKER_LOCK (self);

  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = cur->data;
    gboolean destroy_pending_and_thread_likely_back_in_original_code;

    destroy_pending_and_thread_likely_back_in_original_code =
        g_atomic_int_get (&ctx->state) == GUM_EXEC_CTX_DESTROY_PENDING &&
        (ctx->thread_id == current_thread_id ||
        now - ctx->destroy_pending_since > 20000);

    if (destroy_pending_and_thread_likely_back_in_original_code ||
        !gum_process_has_thread (ctx->thread_id))
    {
      GUM_STALKER_UNLOCK (self);

      gum_stalker_destroy_exec_ctx (self, ctx);

      goto rescan;
    }
  }

  have_pending_garbage = self->contexts != NULL;

  GUM_STALKER_UNLOCK (self);

  return have_pending_garbage;
}

gpointer
_gum_stalker_do_follow_me (GumStalker * self,
                           GumStalkerTransformer * transformer,
                           GumEventSink * sink,
                           gpointer ret_addr)
{
  GumExecCtx * ctx;
  gpointer code_address;

  ctx = gum_stalker_create_exec_ctx (self, gum_process_get_current_thread_id (),
      transformer, sink);
  gum_tls_key_set_value (self->exec_ctx, ctx);

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, ret_addr,
      &code_address);

  if (gum_exec_ctx_maybe_unfollow (ctx, ret_addr))
  {
    gum_stalker_destroy_exec_ctx (self, ctx);
    return ret_addr;
  }

  gum_event_sink_start (ctx->sink);
  ctx->sink_started = TRUE;

  return code_address + GUM_RESTORATION_PROLOG_SIZE;
}

void
gum_stalker_unfollow_me (GumStalker * self)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  if (ctx == NULL)
    return;

  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_UNFOLLOW_PENDING);

  if (!gum_exec_ctx_maybe_unfollow (ctx, NULL))
    return;

  g_assert (ctx->unfollow_called_while_still_following);

  gum_stalker_destroy_exec_ctx (self, ctx);
}

gboolean
gum_stalker_is_following_me (GumStalker * self)
{
  return gum_stalker_get_exec_ctx (self) != NULL;
}

void
gum_stalker_follow (GumStalker * self,
                    GumThreadId thread_id,
                    GumStalkerTransformer * transformer,
                    GumEventSink * sink)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_follow_me (self, transformer, sink);
  }
  else
  {
    GumInfectContext ctx;

    ctx.stalker = self;
    ctx.transformer = transformer;
    ctx.sink = sink;

    gum_process_modify_thread (thread_id, gum_stalker_infect, &ctx);
  }
}

void
gum_stalker_unfollow (GumStalker * self,
                      GumThreadId thread_id)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_unfollow_me (self);
  }
  else
  {
    GumExecCtx * ctx;

    ctx = gum_stalker_find_exec_ctx_by_thread_id (self, thread_id);
    if (ctx == NULL)
      return;

    if (!g_atomic_int_compare_and_exchange (&ctx->state, GUM_EXEC_CTX_ACTIVE,
        GUM_EXEC_CTX_UNFOLLOW_PENDING))
      return;

    if (!gum_exec_ctx_has_executed (ctx))
    {
      GumDisinfectContext dc;

      dc.exec_ctx = ctx;
      dc.success = FALSE;

      gum_process_modify_thread (thread_id, gum_stalker_disinfect, &dc);

      if (dc.success)
        gum_stalker_destroy_exec_ctx (self, ctx);
    }
  }
}

static void
gum_stalker_infect (GumThreadId thread_id,
                    GumCpuContext * cpu_context,
                    gpointer user_data)
{
  GumInfectContext * infect_context = user_data;
  GumStalker * self = infect_context->stalker;
  GumExecCtx * ctx;
  guint8 * pc;
  gpointer code_address;
  GumArm64Writer * cw;
  const guint potential_svc_size = 4;

  ctx = gum_stalker_create_exec_ctx (self, thread_id,
      infect_context->transformer, infect_context->sink);

  pc = GSIZE_TO_POINTER (gum_strip_code_address (cpu_context->pc));

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, pc, &code_address);

  if (gum_exec_ctx_maybe_unfollow (ctx, NULL))
  {
    gum_stalker_destroy_exec_ctx (self, ctx);
    return;
  }

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (self, ctx->thunks, self->thunks_size);
  cw = &ctx->code_writer;
  gum_arm64_writer_reset (cw, ctx->infect_thunk);

  /*
   * In case the thread is in a Linux system call we should allow it to be
   * restarted by bringing along the SVC instruction.
   */
  gum_arm64_writer_put_bytes (cw, pc - potential_svc_size, potential_svc_size);

  ctx->infect_body = GUM_ADDRESS (gum_arm64_writer_cur (cw));
#ifdef HAVE_PTRAUTH
  ctx->infect_body = GPOINTER_TO_SIZE (ptrauth_sign_unauthenticated (
      GSIZE_TO_POINTER (ctx->infect_body), ptrauth_key_process_independent_code,
      ptrauth_string_discriminator ("pc")));
#endif
  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, cw);
  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_tls_key_set_value), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (self->exec_ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx));
  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_arm64_writer_put_b_imm (cw, GUM_ADDRESS (code_address) +
      GUM_RESTORATION_PROLOG_SIZE);

  gum_arm64_writer_flush (cw);
  gum_stalker_freeze (self, cw->base, gum_arm64_writer_offset (cw));

  gum_spinlock_release (&ctx->code_lock);

  gum_event_sink_start (ctx->sink);

  cpu_context->pc = ctx->infect_body;
}

static void
gum_stalker_disinfect (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  GumDisinfectContext * disinfect_context = user_data;
  GumExecCtx * ctx = disinfect_context->exec_ctx;
  gboolean infection_not_active_yet;

  infection_not_active_yet = cpu_context->pc == ctx->infect_body;
  if (infection_not_active_yet)
  {
    cpu_context->pc = gum_sign_code_address (
        GPOINTER_TO_SIZE (ctx->current_block->real_start));

    disinfect_context->success = TRUE;
  }
}

gpointer
_gum_stalker_do_activate (GumStalker * self,
                          gconstpointer target,
                          gpointer ret_addr)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  if (ctx == NULL)
    return ret_addr;

  ctx->unfollow_called_while_still_following = FALSE;
  ctx->activation_target = gum_strip_code_pointer ((gpointer) target);

  if (!gum_exec_ctx_contains (ctx, ret_addr))
  {
    gpointer code_address;

    ctx->current_block =
        gum_exec_ctx_obtain_block_for (ctx, ret_addr, &code_address);

    if (gum_exec_ctx_maybe_unfollow (ctx, ret_addr))
      return ret_addr;

    return code_address + GUM_RESTORATION_PROLOG_SIZE;
  }

  return ret_addr;
}

gpointer
_gum_stalker_do_deactivate (GumStalker * self,
                            gpointer ret_addr)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  if (ctx == NULL)
    return ret_addr;

  ctx->unfollow_called_while_still_following = TRUE;
  ctx->activation_target = NULL;

  if (gum_exec_ctx_contains (ctx, ret_addr))
  {
    ctx->pending_calls--;

    return ctx->pending_return_location;
  }

  return ret_addr;
}

static void
gum_stalker_maybe_deactivate (GumStalker * self,
                              GumActivation * activation)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  activation->ctx = ctx;

  if (ctx != NULL && ctx->pending_calls == 0)
  {
    activation->pending = TRUE;
    activation->target = ctx->activation_target;

    gum_stalker_deactivate (self);
  }
  else
  {
    activation->pending = FALSE;
    activation->target = NULL;
  }
}

static void
gum_stalker_maybe_reactivate (GumStalker * self,
                              GumActivation * activation)
{
  if (activation->pending)
    gum_stalker_activate (self, activation->target);
}

void
gum_stalker_set_observer (GumStalker * self,
                          GumStalkerObserver * observer)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx (self);
  g_assert (ctx != NULL);

  if (observer != NULL)
    g_object_ref (observer);
  if (ctx->observer != NULL)
    g_object_unref (ctx->observer);
  ctx->observer = observer;
}

void
gum_stalker_prefetch (GumStalker * self,
                      gconstpointer address,
                      gint recycle_count)
{
  GumExecCtx * ctx;
  GumExecBlock * block;
  gpointer code_address;

  ctx = gum_stalker_get_exec_ctx (self);
  g_assert (ctx != NULL);

  block = gum_exec_ctx_obtain_block_for (ctx, (gpointer) address,
      &code_address);
  block->recycle_count = recycle_count;
}

void
gum_stalker_prefetch_backpatch (GumStalker * self,
                                const GumBackpatch * backpatch)
{
}

void
gum_stalker_invalidate (GumStalker * self,
                        gconstpointer address)
{
  GumActivation activation;

  gum_stalker_maybe_deactivate (self, &activation);
  if (activation.ctx == NULL)
    return;

  gum_stalker_do_invalidate (activation.ctx, address, &activation);

  gum_stalker_maybe_reactivate (self, &activation);
}

void
gum_stalker_invalidate_for_thread (GumStalker * self,
                                   GumThreadId thread_id,
                                   gconstpointer address)
{
  GumActivation activation;
  GumExecCtx * ctx;

  gum_stalker_maybe_deactivate (self, &activation);

  ctx = gum_stalker_find_exec_ctx_by_thread_id (self, thread_id);
  if (ctx != NULL)
  {
    while (!gum_stalker_do_invalidate (ctx, address, &activation))
    {
      g_thread_yield ();
    }
  }

  gum_stalker_maybe_reactivate (self, &activation);
}

static void
gum_stalker_invalidate_for_all_threads (GumStalker * self,
                                        gconstpointer address,
                                        GumActivation * activation)
{
  GSList * contexts, * cur;

  GUM_STALKER_LOCK (self);
  contexts = g_slist_copy (self->contexts);
  GUM_STALKER_UNLOCK (self);

  cur = contexts;

  while (cur != NULL)
  {
    GumExecCtx * ctx = cur->data;
    GSList * l;

    if (!gum_stalker_do_invalidate (ctx, address, activation))
    {
      cur = g_slist_append (cur, ctx);
    }

    l = cur;
    cur = cur->next;
    g_slist_free_1 (l);
  }
}

static gboolean
gum_stalker_do_invalidate (GumExecCtx * ctx,
                           gconstpointer address,
                           GumActivation * activation)
{
  GumInvalidateContext ic;

  ic.is_executing_target_block = FALSE;

  gum_spinlock_acquire (&ctx->code_lock);

  if ((ic.block = gum_metal_hash_table_lookup (ctx->mappings, address)) != NULL)
  {
    if (ctx == activation->ctx)
    {
      gum_exec_block_invalidate (ic.block);
    }
    else
    {
      gum_process_modify_thread (ctx->thread_id,
          gum_stalker_try_invalidate_block_owned_by_thread, &ic);
    }
  }

  gum_spinlock_release (&ctx->code_lock);

  return !ic.is_executing_target_block;
}

static void
gum_stalker_try_invalidate_block_owned_by_thread (GumThreadId thread_id,
                                                  GumCpuContext * cpu_context,
                                                  gpointer user_data)
{
  GumInvalidateContext * ic = user_data;
  GumExecBlock * block = ic->block;
  const guint8 * pc = GSIZE_TO_POINTER (cpu_context->pc);

  if (pc >= block->code_start &&
      pc < block->code_start + GUM_INVALIDATE_TRAMPOLINE_MAX_SIZE)
  {
    ic->is_executing_target_block = TRUE;
    return;
  }

  gum_exec_block_invalidate (block);
}

GumProbeId
gum_stalker_add_call_probe (GumStalker * self,
                            gpointer target_address,
                            GumCallProbeCallback callback,
                            gpointer data,
                            GDestroyNotify notify)
{
  GumActivation activation;
  GumCallProbe * probe;
  GPtrArray * probes;
  gboolean is_first_for_target;

  gum_stalker_maybe_deactivate (self, &activation);

  target_address = gum_strip_code_pointer (target_address);
  is_first_for_target = FALSE;

  probe = g_slice_new (GumCallProbe);
  probe->ref_count = 1;
  probe->id = g_atomic_int_add (&self->last_probe_id, 1) + 1;
  probe->callback = callback;
  probe->user_data = data;
  probe->user_notify = notify;

  gum_spinlock_acquire (&self->probe_lock);

  g_hash_table_insert (self->probe_target_by_id, GSIZE_TO_POINTER (probe->id),
      target_address);

  probes = g_hash_table_lookup (self->probe_array_by_address, target_address);
  if (probes == NULL)
  {
    probes =
        g_ptr_array_new_with_free_func ((GDestroyNotify) gum_call_probe_unref);
    g_hash_table_insert (self->probe_array_by_address, target_address, probes);

    is_first_for_target = TRUE;
  }

  g_ptr_array_add (probes, probe);

  self->any_probes_attached = TRUE;

  gum_spinlock_release (&self->probe_lock);

  if (is_first_for_target)
    gum_stalker_invalidate_for_all_threads (self, target_address, &activation);

  gum_stalker_maybe_reactivate (self, &activation);

  return probe->id;
}

void
gum_stalker_remove_call_probe (GumStalker * self,
                               GumProbeId id)
{
  GumActivation activation;
  gpointer target_address;
  gboolean is_last_for_target;

  gum_stalker_maybe_deactivate (self, &activation);

  gum_spinlock_acquire (&self->probe_lock);

  target_address =
      g_hash_table_lookup (self->probe_target_by_id, GSIZE_TO_POINTER (id));
  is_last_for_target = FALSE;

  if (target_address != NULL)
  {
    GPtrArray * probes;
    gint match_index = -1;
    guint i;

    g_hash_table_remove (self->probe_target_by_id, GSIZE_TO_POINTER (id));

    probes = g_hash_table_lookup (self->probe_array_by_address, target_address);
    g_assert (probes != NULL);

    for (i = 0; i != probes->len; i++)
    {
      GumCallProbe * probe = g_ptr_array_index (probes, i);
      if (probe->id == id)
      {
        match_index = i;
        break;
      }
    }
    g_assert (match_index != -1);

    g_ptr_array_remove_index (probes, match_index);

    if (probes->len == 0)
    {
      g_hash_table_remove (self->probe_array_by_address, target_address);

      is_last_for_target = TRUE;
    }

    self->any_probes_attached =
        g_hash_table_size (self->probe_array_by_address) != 0;
  }

  gum_spinlock_release (&self->probe_lock);

  if (is_last_for_target)
    gum_stalker_invalidate_for_all_threads (self, target_address, &activation);

  gum_stalker_maybe_reactivate (self, &activation);
}

static void
gum_call_probe_finalize (GumCallProbe * probe)
{
  if (probe->user_notify != NULL)
    probe->user_notify (probe->user_data);
}

static GumCallProbe *
gum_call_probe_ref (GumCallProbe * probe)
{
  g_atomic_int_inc (&probe->ref_count);

  return probe;
}

static void
gum_call_probe_unref (GumCallProbe * probe)
{
  if (g_atomic_int_dec_and_test (&probe->ref_count))
  {
    gum_call_probe_finalize (probe);
  }
}

static GumExecCtx *
gum_stalker_create_exec_ctx (GumStalker * self,
                             GumThreadId thread_id,
                             GumStalkerTransformer * transformer,
                             GumEventSink * sink)
{
  GumExecCtx * ctx = gum_exec_ctx_new (self, thread_id, transformer, sink);

  GUM_STALKER_LOCK (self);
  self->contexts = g_slist_prepend (self->contexts, ctx);
  GUM_STALKER_UNLOCK (self);

  return ctx;
}

static void
gum_stalker_destroy_exec_ctx (GumStalker * self,
                              GumExecCtx * ctx)
{
  GSList * entry;

  GUM_STALKER_LOCK (self);
  entry = g_slist_find (self->contexts, ctx);
  if (entry != NULL)
    self->contexts = g_slist_delete_link (self->contexts, entry);
  GUM_STALKER_UNLOCK (self);

  /* Racy due to garbage-collection. */
  if (entry == NULL)
    return;

  gum_exec_ctx_dispose (ctx);

  if (ctx->sink_started)
  {
    gum_event_sink_stop (ctx->sink);

    ctx->sink_started = FALSE;
  }

  gum_exec_ctx_free (ctx);
}

static GumExecCtx *
gum_stalker_get_exec_ctx (GumStalker * self)
{
  return gum_tls_key_get_value (self->exec_ctx);
}

static GumExecCtx *
gum_stalker_find_exec_ctx_by_thread_id (GumStalker * self,
                                        GumThreadId thread_id)
{
  GumExecCtx * ctx = NULL;
  GSList * cur;

  GUM_STALKER_LOCK (self);

  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * candidate = cur->data;

    if (candidate->thread_id == thread_id)
    {
      ctx = candidate;
      break;
    }
  }

  GUM_STALKER_UNLOCK (self);

  return ctx;
}

static gsize
gum_stalker_snapshot_space_needed_for (GumStalker * self,
                                       gsize real_size)
{
  return (self->trust_threshold != 0) ? real_size : 0;
}

static void
gum_stalker_thaw (GumStalker * self,
                  gpointer code,
                  gsize size)
{
  if (!self->is_rwx_supported)
    gum_mprotect (code, size, GUM_PAGE_RW);
}

static void
gum_stalker_freeze (GumStalker * self,
                    gpointer code,
                    gsize size)
{
  if (!self->is_rwx_supported)
    gum_memory_mark_code (code, size);

  gum_clear_cache (code, size);
}

static gboolean
gum_stalker_on_exception (GumExceptionDetails * details,
                          gpointer user_data)
{
  GumStalker * self = user_data;
  GumExecCtx * ctx;

  ctx = gum_stalker_find_exec_ctx_by_thread_id (self, details->thread_id);
  if (ctx == NULL)
    return FALSE;

  return gum_exec_ctx_try_handle_exception (ctx, details);
}

static GumExecCtx *
gum_exec_ctx_new (GumStalker * stalker,
                  GumThreadId thread_id,
                  GumStalkerTransformer * transformer,
                  GumEventSink * sink)
{
  GumExecCtx * ctx;
  guint8 * base;
  GumCodeSlab * code_slab;
  GumDataSlab * data_slab;

  base = gum_memory_allocate (NULL, stalker->ctx_size, stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  ctx = (GumExecCtx *) base;

  ctx->state = GUM_EXEC_CTX_ACTIVE;

  ctx->stalker = g_object_ref (stalker);
  ctx->thread_id = thread_id;

  gum_arm64_writer_init (&ctx->code_writer, NULL);
  gum_arm64_relocator_init (&ctx->relocator, NULL, &ctx->code_writer);

  if (transformer != NULL)
    ctx->transformer = g_object_ref (transformer);
  else
    ctx->transformer = gum_stalker_transformer_make_default ();
  ctx->transform_block_impl =
      GUM_STALKER_TRANSFORMER_GET_IFACE (ctx->transformer)->transform_block;

  if (sink != NULL)
    ctx->sink = g_object_ref (sink);
  else
    ctx->sink = gum_event_sink_make_default ();

  ctx->sink_mask = gum_event_sink_query_mask (ctx->sink);
  ctx->sink_process_impl = GUM_EVENT_SINK_GET_IFACE (ctx->sink)->process;

  ctx->observer = NULL;

  ctx->frames = (GumExecFrame *) (base + stalker->frames_offset);
  ctx->first_frame =
      ctx->frames + (stalker->frames_size / sizeof (GumExecFrame)) - 1;
  ctx->current_frame = ctx->first_frame;

  ctx->thunks = base + stalker->thunks_offset;
  ctx->infect_thunk = ctx->thunks;

  gum_spinlock_init (&ctx->code_lock);

  code_slab = (GumCodeSlab *) (base + stalker->code_slab_offset);
  gum_code_slab_init (code_slab, stalker->code_slab_size_initial,
      stalker->page_size);
  gum_exec_ctx_add_code_slab (ctx, code_slab);

  data_slab = (GumDataSlab *) (base + stalker->data_slab_offset);
  gum_data_slab_init (data_slab, stalker->data_slab_size_initial);
  gum_exec_ctx_add_data_slab (ctx, data_slab);

  ctx->scratch_slab = (GumCodeSlab *) (base + stalker->scratch_slab_offset);
  gum_scratch_slab_init (ctx->scratch_slab, stalker->scratch_slab_size);

  ctx->mappings = gum_metal_hash_table_new (NULL, NULL);

  gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

  code_slab->invalidator = ctx->last_invalidator;

  return ctx;
}

static void
gum_exec_ctx_free (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumDataSlab * data_slab;
  GumCodeSlab * code_slab;

  gum_metal_hash_table_unref (ctx->mappings);

  data_slab = ctx->data_slab;
  while (TRUE)
  {
    GumDataSlab * next = (GumDataSlab *) data_slab->slab.next;
    gboolean is_initial;

    is_initial = next == NULL;
    if (is_initial)
      break;

    gum_data_slab_free (data_slab);

    data_slab = next;
  }

  code_slab = ctx->code_slab;
  while (TRUE)
  {
    GumCodeSlab * next = (GumCodeSlab *) code_slab->slab.next;
    gboolean is_initial;

    is_initial = next == NULL;
    if (is_initial)
      break;

    gum_code_slab_free (code_slab);

    code_slab = next;
  }

  g_object_unref (ctx->sink);
  g_object_unref (ctx->transformer);
  g_clear_object (&ctx->observer);

  gum_arm64_relocator_clear (&ctx->relocator);
  gum_arm64_writer_clear (&ctx->code_writer);

  g_object_unref (stalker);

  gum_memory_free (ctx, stalker->ctx_size);
}

static void
gum_exec_ctx_dispose (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumSlab * slab;

  for (slab = &ctx->code_slab->slab; slab != NULL; slab = slab->next)
  {
    gum_stalker_thaw (stalker, gum_slab_start (slab), slab->offset);
  }

  for (slab = &ctx->data_slab->slab; slab != NULL; slab = slab->next)
  {
    GumExecBlock * blocks;
    guint num_blocks;
    guint i;

    blocks = gum_slab_start (slab);
    num_blocks = slab->offset / sizeof (GumExecBlock);

    for (i = 0; i != num_blocks; i++)
    {
      GumExecBlock * block = &blocks[i];

      gum_exec_block_clear (block);
    }
  }
}

static GumCodeSlab *
gum_exec_ctx_add_code_slab (GumExecCtx * ctx,
                            GumCodeSlab * code_slab)
{
  code_slab->slab.next = &ctx->code_slab->slab;
  ctx->code_slab = code_slab;
  return code_slab;
}

static GumDataSlab *
gum_exec_ctx_add_data_slab (GumExecCtx * ctx,
                            GumDataSlab * data_slab)
{
  data_slab->slab.next = &ctx->data_slab->slab;
  ctx->data_slab = data_slab;
  return data_slab;
}

static void
gum_exec_ctx_compute_code_address_spec (GumExecCtx * ctx,
                                        gsize slab_size,
                                        GumAddressSpec * spec)
{
  GumStalker * stalker = ctx->stalker;

  /* Code must be able to reference ExecCtx fields using 32-bit offsets. */
  spec->near_address = ctx;
  spec->max_distance = G_MAXINT32 - stalker->ctx_size - slab_size;
}

static void
gum_exec_ctx_compute_data_address_spec (GumExecCtx * ctx,
                                        gsize slab_size,
                                        GumAddressSpec * spec)
{
  GumStalker * stalker = ctx->stalker;

  /* Code must be able to reference ExecBlock fields using 32-bit offsets. */
  spec->near_address = ctx->code_slab;
  spec->max_distance = G_MAXINT32 - stalker->code_slab_size_dynamic - slab_size;
}

static gboolean
gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
                             gpointer resume_at)
{
  if (g_atomic_int_get (&ctx->state) != GUM_EXEC_CTX_UNFOLLOW_PENDING)
    return FALSE;

  if (ctx->pending_calls > 0)
    return FALSE;

  gum_exec_ctx_unfollow (ctx, resume_at);

  return TRUE;
}

static void
gum_exec_ctx_unfollow (GumExecCtx * ctx,
                       gpointer resume_at)
{
  ctx->current_block = NULL;

  ctx->resume_at = resume_at;

  gum_tls_key_set_value (ctx->stalker->exec_ctx, NULL);

  ctx->destroy_pending_since = g_get_monotonic_time ();
  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_DESTROY_PENDING);
}

static gboolean
gum_exec_ctx_has_executed (GumExecCtx * ctx)
{
  return ctx->resume_at != NULL;
}

static gboolean
gum_exec_ctx_contains (GumExecCtx * ctx,
                       gconstpointer address)
{
  GumSlab * cur = &ctx->code_slab->slab;

  do {
    if ((const guint8 *) address >= cur->data &&
        (const guint8 *) address < (guint8 *) gum_slab_cursor (cur))
    {
      return TRUE;
    }

    cur = cur->next;
  } while (cur != NULL);

  return FALSE;
}

static gboolean
gum_exec_ctx_may_now_backpatch (GumExecCtx * ctx,
                                GumExecBlock * target_block)
{
  if (g_atomic_int_get (&ctx->state) != GUM_EXEC_CTX_ACTIVE)
    return FALSE;

  if ((target_block->flags & GUM_EXEC_BLOCK_ACTIVATION_TARGET) != 0)
    return FALSE;

  if (target_block->recycle_count < ctx->stalker->trust_threshold)
    return FALSE;

  return TRUE;
}

#define GUM_ENTRYGATE(name) \
    gum_exec_ctx_replace_current_block_from_##name
#define GUM_DEFINE_ENTRYGATE(name) \
    static gpointer GUM_THUNK \
    GUM_ENTRYGATE (name) ( \
        GumExecCtx * ctx, \
        gpointer start_address) \
    { \
      if (ctx->observer != NULL) \
        gum_stalker_observer_increment_##name (ctx->observer); \
      \
      return gum_exec_ctx_switch_block (ctx, start_address); \
    }

GUM_DEFINE_ENTRYGATE (call_imm)
GUM_DEFINE_ENTRYGATE (call_reg)
GUM_DEFINE_ENTRYGATE (post_call_invoke)
GUM_DEFINE_ENTRYGATE (excluded_call_imm)
GUM_DEFINE_ENTRYGATE (excluded_call_reg)
GUM_DEFINE_ENTRYGATE (ret)

GUM_DEFINE_ENTRYGATE (jmp_imm)
GUM_DEFINE_ENTRYGATE (jmp_reg)

GUM_DEFINE_ENTRYGATE (jmp_cond_cc)
GUM_DEFINE_ENTRYGATE (jmp_cond_cbz)
GUM_DEFINE_ENTRYGATE (jmp_cond_cbnz)
GUM_DEFINE_ENTRYGATE (jmp_cond_tbz)
GUM_DEFINE_ENTRYGATE (jmp_cond_tbnz)

GUM_DEFINE_ENTRYGATE (jmp_continuation)

static gpointer
gum_exec_ctx_switch_block (GumExecCtx * ctx,
                           gpointer start_address)
{
  if (ctx->observer != NULL)
    gum_stalker_observer_increment_total (ctx->observer);

  if (start_address == gum_unfollow_me_address ||
      start_address == gum_deactivate_address)
  {
    ctx->unfollow_called_while_still_following = TRUE;
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  else if (start_address == gum_thread_exit_address)
  {
    gum_exec_ctx_unfollow (ctx, start_address);
  }
  else if (gum_exec_ctx_maybe_unfollow (ctx, start_address))
  {
  }
  else if (gum_exec_ctx_contains (ctx, start_address))
  {
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  else
  {
    ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, start_address,
        &ctx->resume_at);

    if (start_address == ctx->activation_target)
    {
      ctx->activation_target = NULL;
      ctx->current_block->flags |= GUM_EXEC_BLOCK_ACTIVATION_TARGET;
    }

    gum_exec_ctx_maybe_unfollow (ctx, start_address);
  }

  return ctx->resume_at;
}

static void
gum_exec_ctx_recompile_and_switch_block (GumExecCtx * ctx,
                                         GumExecBlock * block)
{
  const gpointer start_address = block->real_start;

  if (gum_exec_ctx_maybe_unfollow (ctx, start_address))
    return;

  gum_exec_ctx_recompile_block (ctx, block);

  ctx->current_block = block;
  ctx->resume_at = block->code_start;

  if (start_address == ctx->activation_target)
  {
    ctx->activation_target = NULL;
    ctx->current_block->flags |= GUM_EXEC_BLOCK_ACTIVATION_TARGET;
  }

  gum_exec_ctx_maybe_unfollow (ctx, start_address);
}

static void
gum_exec_ctx_begin_call (GumExecCtx * ctx,
                         gpointer ret_addr)
{
  ctx->pending_return_location = ret_addr;
  ctx->pending_calls++;
}

static void
gum_exec_ctx_end_call (GumExecCtx * ctx)
{
  ctx->pending_calls--;
}

static GumExecBlock *
gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
                               gpointer real_address,
                               gpointer * code_address)
{
  GumExecBlock * block;

  gum_spinlock_acquire (&ctx->code_lock);

  block = gum_metal_hash_table_lookup (ctx->mappings, real_address);
  if (block != NULL)
  {
    const gint trust_threshold = ctx->stalker->trust_threshold;
    gboolean still_up_to_date;

    still_up_to_date =
        (trust_threshold >= 0 && block->recycle_count >= trust_threshold) ||
        memcmp (block->real_start, gum_exec_block_get_snapshot_start (block),
            block->real_size) == 0;

    gum_spinlock_release (&ctx->code_lock);

    if (still_up_to_date)
    {
      if (trust_threshold > 0)
        block->recycle_count++;
    }
    else
    {
      gum_exec_ctx_recompile_block (ctx, block);
    }
  }
  else
  {
    block = gum_exec_block_new (ctx);
    block->real_start = real_address;
    gum_exec_ctx_compile_block (ctx, block, real_address, block->code_start,
        GUM_ADDRESS (block->code_start), &block->real_size, &block->code_size);
    gum_exec_block_commit (block);

    gum_metal_hash_table_insert (ctx->mappings, real_address, block);

    gum_spinlock_release (&ctx->code_lock);

    gum_exec_ctx_maybe_emit_compile_event (ctx, block);
  }

  *code_address = block->code_start;

  return block;
}

static void
gum_exec_ctx_recompile_block (GumExecCtx * ctx,
                              GumExecBlock * block)
{
  GumStalker * stalker = ctx->stalker;
  guint8 * internal_code = block->code_start;
  GumCodeSlab * slab;
  guint8 * scratch_base;
  guint input_size, output_size;
  gsize new_snapshot_size, new_block_size;

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (stalker, internal_code, block->capacity);

  if (block->storage_block != NULL)
    gum_exec_block_clear (block->storage_block);
  gum_exec_block_clear (block);

  slab = block->code_slab;
  block->code_slab = ctx->scratch_slab;
  scratch_base = ctx->scratch_slab->slab.data;

  gum_exec_ctx_compile_block (ctx, block, block->real_start, scratch_base,
      GUM_ADDRESS (internal_code), &input_size, &output_size);

  block->code_slab = slab;

  new_snapshot_size =
      gum_stalker_snapshot_space_needed_for (stalker, input_size);

  new_block_size = output_size + new_snapshot_size;

  if (new_block_size <= block->capacity)
  {
    block->real_size = input_size;
    block->code_size = output_size;

    memcpy (internal_code, scratch_base, output_size);
    memcpy (gum_exec_block_get_snapshot_start (block), block->real_start,
        new_snapshot_size);

    gum_stalker_freeze (stalker, internal_code, new_block_size);
  }
  else
  {
    GumExecBlock * storage_block;
    GumArm64Writer * cw = &ctx->code_writer;
    GumAddress external_code_address;

    storage_block = gum_exec_block_new (ctx);
    storage_block->real_start = block->real_start;
    gum_exec_ctx_compile_block (ctx, block, block->real_start,
        storage_block->code_start, GUM_ADDRESS (storage_block->code_start),
        &storage_block->real_size, &storage_block->code_size);
    gum_exec_block_commit (storage_block);

    block->storage_block = storage_block;

    gum_stalker_thaw (stalker, internal_code, block->capacity);
    gum_arm64_writer_reset (cw, internal_code);

    external_code_address = GUM_ADDRESS (storage_block->code_start);
    if (gum_arm64_writer_can_branch_directly_between (cw,
        GUM_ADDRESS (internal_code), external_code_address))
    {
      gum_arm64_writer_put_b_imm (cw, external_code_address);
      gum_arm64_writer_put_b_imm (cw, external_code_address + sizeof (guint32));
    }
    else
    {
      gconstpointer already_saved = cw->code + 1;

      gum_arm64_writer_put_b_label (cw, already_saved);
      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
          ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
          GUM_INDEX_PRE_ADJUST);
      gum_arm64_writer_put_label (cw, already_saved);
      gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
          external_code_address);
      gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X16);
    }

    gum_arm64_writer_flush (cw);
    gum_stalker_freeze (stalker, internal_code, block->capacity);
  }

  gum_spinlock_release (&ctx->code_lock);

  gum_exec_ctx_maybe_emit_compile_event (ctx, block);
}

static void
gum_exec_ctx_compile_block (GumExecCtx * ctx,
                            GumExecBlock * block,
                            gconstpointer input_code,
                            gpointer output_code,
                            GumAddress output_pc,
                            guint * input_size,
                            guint * output_size)
{
  GumArm64Writer * cw = &ctx->code_writer;
  GumArm64Relocator * rl = &ctx->relocator;
  GumGeneratorContext gc;
  GumStalkerIterator iterator;
  GumStalkerOutput output;
  gboolean all_labels_resolved;

  gum_arm64_writer_reset (cw, output_code);
  cw->pc = output_pc;
  gum_arm64_relocator_reset (rl, input_code, cw);

  gum_ensure_code_readable (input_code, ctx->stalker->page_size);

  gc.instruction = NULL;
  gc.relocator = rl;
  gc.code_writer = cw;
  gc.continuation_real_address = NULL;
  gc.opened_prolog = GUM_PROLOG_NONE;
  gc.exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;

  iterator.exec_context = ctx;
  iterator.exec_block = block;
  iterator.generator_context = &gc;

  iterator.instruction.ci = NULL;
  iterator.instruction.start = NULL;
  iterator.instruction.end = NULL;
  iterator.requirements = GUM_REQUIRE_NOTHING;

  output.writer.arm64 = cw;
  output.encoding = GUM_INSTRUCTION_DEFAULT;

  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);

  gum_exec_block_maybe_write_call_probe_code (block, &gc);

  ctx->pending_calls++;
  ctx->transform_block_impl (ctx->transformer, &iterator, &output);
  ctx->pending_calls--;

  if (gc.continuation_real_address != NULL)
  {
    GumBranchTarget continue_target = { 0, };

    continue_target.absolute_address = gc.continuation_real_address;
    continue_target.reg = ARM64_REG_INVALID;
    gum_exec_block_write_jmp_transfer_code (block, &continue_target,
        GUM_ENTRYGATE (jmp_continuation), &gc);
  }

  gum_arm64_writer_put_brk_imm (cw, 14);

  all_labels_resolved = gum_arm64_writer_flush (cw);
  if (!all_labels_resolved)
    gum_panic ("Failed to resolve labels");

  *input_size = rl->input_cur - rl->input_start;
  *output_size = gum_arm64_writer_offset (cw);
}

static void
gum_exec_ctx_maybe_emit_compile_event (GumExecCtx * ctx,
                                       GumExecBlock * block)
{
  if ((ctx->sink_mask & GUM_COMPILE) != 0)
  {
    GumEvent ev;

    ev.type = GUM_COMPILE;
    ev.compile.start = block->real_start;
    ev.compile.end = block->real_start + block->real_size;

    ctx->sink_process_impl (ctx->sink, &ev, NULL);
  }
}

gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;
  GumArm64Relocator * rl = gc->relocator;
  GumInstruction * instruction;
  gboolean is_first_instruction;
  guint n_read;

  instruction = self->generator_context->instruction;
  is_first_instruction = instruction == NULL;

  if (instruction != NULL)
  {
    gboolean skip_implicitly_requested;

    skip_implicitly_requested = rl->outpos != rl->inpos;
    if (skip_implicitly_requested)
    {
      gum_arm64_relocator_skip_one (rl);
    }

    if (gum_stalker_iterator_is_out_of_space (self))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }
    else if ((self->requirements & GUM_REQUIRE_EXCLUSIVE_STORE) == 0 &&
        gum_arm64_relocator_eob (rl))
    {
      return FALSE;
    }

    switch (instruction->ci->id)
    {
      case ARM64_INS_STXR:
      case ARM64_INS_STXP:
      case ARM64_INS_STXRB:
      case ARM64_INS_STXRH:
      case ARM64_INS_STLXR:
      case ARM64_INS_STLXP:
      case ARM64_INS_STLXRB:
      case ARM64_INS_STLXRH:
        gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;
        break;
      default:
        break;
    }

    if (gc->exclusive_load_offset != GUM_INSTRUCTION_OFFSET_NONE)
    {
      gc->exclusive_load_offset++;
      if (gc->exclusive_load_offset == 4)
        gc->exclusive_load_offset = GUM_INSTRUCTION_OFFSET_NONE;
    }
  }

  instruction = &self->instruction;

  n_read = gum_arm64_relocator_read_one (rl, &instruction->ci);
  if (n_read == 0)
    return FALSE;

  instruction->start = GSIZE_TO_POINTER (instruction->ci->address);
  instruction->end = instruction->start + instruction->ci->size;

  self->generator_context->instruction = instruction;

  if (is_first_instruction && (self->exec_context->sink_mask & GUM_BLOCK) != 0)
  {
    gum_exec_block_write_block_event_code (self->exec_block, gc,
        GUM_CODE_INTERRUPTIBLE);
  }

  if (insn != NULL)
    *insn = instruction->ci;

  return TRUE;
}

static gboolean
gum_stalker_iterator_is_out_of_space (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumSlab * slab = &block->code_slab->slab;
  gsize capacity, snapshot_size;

  capacity = (guint8 *) gum_slab_end (slab) -
      (guint8 *) gum_arm64_writer_cur (self->generator_context->code_writer);

  snapshot_size = gum_stalker_snapshot_space_needed_for (
      self->exec_context->stalker,
      self->generator_context->instruction->end - block->real_start);

  return capacity < GUM_EXEC_BLOCK_MIN_CAPACITY + snapshot_size;
}

void
gum_stalker_iterator_keep (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumArm64Relocator * rl = gc->relocator;
  const cs_insn * insn = gc->instruction->ci;
  GumVirtualizationRequirements requirements;

  requirements = GUM_REQUIRE_NOTHING;

  switch (insn->id)
  {
    case ARM64_INS_LDAXR:
    case ARM64_INS_LDAXP:
    case ARM64_INS_LDAXRB:
    case ARM64_INS_LDAXRH:
    case ARM64_INS_LDXR:
    case ARM64_INS_LDXP:
    case ARM64_INS_LDXRB:
    case ARM64_INS_LDXRH:
      gc->exclusive_load_offset = 0;
      break;
    default:
      break;
  }

  if ((self->exec_context->sink_mask & GUM_EXEC) != 0 &&
      gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE)
  {
    gum_exec_block_write_exec_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);
  }

  switch (insn->id)
  {
    case ARM64_INS_B:
    case ARM64_INS_BR:
    case ARM64_INS_BRAA:
    case ARM64_INS_BRAAZ:
    case ARM64_INS_BRAB:
    case ARM64_INS_BRABZ:
    case ARM64_INS_BL:
    case ARM64_INS_BLR:
    case ARM64_INS_BLRAA:
    case ARM64_INS_BLRAAZ:
    case ARM64_INS_BLRAB:
    case ARM64_INS_BLRABZ:
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
      requirements = gum_exec_block_virtualize_branch_insn (block, gc);
      break;
    case ARM64_INS_RET:
    case ARM64_INS_RETAA:
    case ARM64_INS_RETAB:
      requirements = gum_exec_block_virtualize_ret_insn (block, gc);
      break;
    case ARM64_INS_SVC:
      requirements = gum_exec_block_virtualize_sysenter_insn (block, gc);
      break;
    case ARM64_INS_SMC:
    case ARM64_INS_HVC:
      g_assert_not_reached ();
      break;
    default:
      requirements = GUM_REQUIRE_RELOCATION;
  }

  gum_exec_block_close_prolog (block, gc);

  if ((requirements & GUM_REQUIRE_RELOCATION) != 0)
    gum_arm64_relocator_write_one (rl);

  self->requirements = requirements;
}

static void
gum_exec_ctx_emit_call_event (GumExecCtx * ctx,
                              gpointer location,
                              gpointer target,
                              GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumCallEvent * call = &ev.call;

  ev.type = GUM_CALL;

  call->location = location;
  call->target = target;
  call->depth = ctx->first_frame - ctx->current_frame;

  cpu_context->pc = GPOINTER_TO_SIZE (location);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

static void
gum_exec_ctx_emit_ret_event (GumExecCtx * ctx,
                             gpointer location,
                             gpointer target,
                             GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumRetEvent * ret = &ev.ret;

  ev.type = GUM_RET;

  ret->location = location;
  ret->target = target;
  ret->depth = ctx->first_frame - ctx->current_frame;

  cpu_context->pc = GPOINTER_TO_SIZE (location);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

static void
gum_exec_ctx_emit_exec_event (GumExecCtx * ctx,
                              gpointer location,
                              GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumExecEvent * exec = &ev.exec;

  ev.type = GUM_EXEC;

  exec->location = location;

  cpu_context->pc = GPOINTER_TO_SIZE (location);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

static void
gum_exec_ctx_emit_block_event (GumExecCtx * ctx,
                               const GumExecBlock * block,
                               GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumBlockEvent * bev = &ev.block;

  ev.type = GUM_BLOCK;

  bev->start = block->real_start;
  bev->end = block->real_start + block->real_size;

  cpu_context->pc = GPOINTER_TO_SIZE (block->real_start);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

void
gum_stalker_iterator_put_callout (GumStalkerIterator * self,
                                  GumStalkerCallout callout,
                                  gpointer data,
                                  GDestroyNotify data_destroy)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumArm64Writer * cw = gc->code_writer;
  GumCalloutEntry entry;
  GumAddress entry_address;

  entry.callout = callout;
  entry.data = data;
  entry.data_destroy = data_destroy;
  entry.pc = gc->instruction->start;
  entry.exec_context = self->exec_context;
  entry.next = gum_exec_block_get_last_callout_entry (block);
  gum_exec_block_write_inline_data (cw, &entry, sizeof (entry), &entry_address);

  gum_exec_block_set_last_callout_entry (block,
      GSIZE_TO_POINTER (entry_address));

  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc);
  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_stalker_invoke_callout), 2,
      GUM_ARG_ADDRESS, entry_address,
      GUM_ARG_REGISTER, ARM64_REG_X20);
  gum_exec_block_close_prolog (block, gc);
}

static void
gum_stalker_invoke_callout (GumCalloutEntry * entry,
                            GumCpuContext * cpu_context)
{
  GumExecCtx * ec = entry->exec_context;

  cpu_context->pc = GPOINTER_TO_SIZE (entry->pc);

  ec->pending_calls++;
  entry->callout (cpu_context, entry->data);
  ec->pending_calls--;
}

static void
gum_exec_ctx_write_prolog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
  gpointer helper;

  helper = (type == GUM_PROLOG_MINIMAL)
      ? ctx->last_prolog_minimal
      : ctx->last_prolog_full;

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19,
      ARM64_REG_LR, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (helper));
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
  gpointer helper;

  helper = (type == GUM_PROLOG_MINIMAL)
      ? ctx->last_epilog_minimal
      : ctx->last_epilog_full;

  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (helper));
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X19,
      ARM64_REG_X20, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
}

static void
gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx)
{
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_prolog_minimal,
      gum_exec_ctx_write_minimal_prolog_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_epilog_minimal,
      gum_exec_ctx_write_minimal_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_prolog_full,
      gum_exec_ctx_write_full_prolog_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_epilog_full,
      gum_exec_ctx_write_full_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_stack_push,
      gum_exec_ctx_write_stack_push_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_stack_pop_and_go,
      gum_exec_ctx_write_stack_pop_and_go_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_invalidator,
      gum_exec_ctx_write_invalidator);
}

static void
gum_exec_ctx_write_minimal_prolog_helper (GumExecCtx * ctx,
                                          GumArm64Writer * cw)
{
  gum_exec_ctx_write_prolog_helper (ctx, GUM_PROLOG_MINIMAL, cw);
}

static void
gum_exec_ctx_write_minimal_epilog_helper (GumExecCtx * ctx,
                                          GumArm64Writer * cw)
{
  gum_exec_ctx_write_epilog_helper (ctx, GUM_PROLOG_MINIMAL, cw);
}

static void
gum_exec_ctx_write_full_prolog_helper (GumExecCtx * ctx,
                                       GumArm64Writer * cw)
{
  gum_exec_ctx_write_prolog_helper (ctx, GUM_PROLOG_FULL, cw);
}

static void
gum_exec_ctx_write_full_epilog_helper (GumExecCtx * ctx,
                                       GumArm64Writer * cw)
{
  gum_exec_ctx_write_epilog_helper (ctx, GUM_PROLOG_FULL, cw);
}

static void
gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumArm64Writer * cw)
{
  const guint32 mrs_x15_nzcv = 0xd53b420f;

  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_LR, ARM64_REG_SP, 8);
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X20, ARM64_REG_SP,
      8);

  if (type == GUM_PROLOG_MINIMAL)
  {
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q6, ARM64_REG_Q7);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q0, ARM64_REG_Q1);

    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X29, ARM64_REG_X30);
    /* X19 - X28 are callee-saved registers */
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X18, ARM64_REG_X30);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
  }
  else if (type == GUM_PROLOG_FULL)
  {
    /* GumCpuContext.q[128] */
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q6, ARM64_REG_Q7);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_Q0, ARM64_REG_Q1);

    /* GumCpuContext.x[29] + fp + lr + padding */
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X30, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X28, ARM64_REG_X29);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X26, ARM64_REG_X27);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X24, ARM64_REG_X25);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X22, ARM64_REG_X23);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X20, ARM64_REG_X21);

    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X20, ARM64_REG_X19);
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X19, ARM64_REG_SP,
        (6 * 16) + (4 * 32));

    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X18, ARM64_REG_X19);

    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_X20);

    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);

    /* GumCpuContext.pc + sp */
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X0, ARM64_REG_XZR);

    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X1, ARM64_REG_SP,
        (16 * 16) + (4 * 32) + 16 + GUM_RED_ZONE_SIZE);
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X2,
        GUM_ADDRESS (&ctx->pending_stack_misalignment));
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_W2, ARM64_REG_X2, 0);
    gum_arm64_writer_put_add_reg_reg_reg (cw, ARM64_REG_X1, ARM64_REG_X1,
        ARM64_REG_X2);

    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
  }

  gum_arm64_writer_put_instruction (cw, mrs_x15_nzcv);

  /* conveniently point X20 at the start of the saved registers */
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X20, ARM64_REG_SP);

  /* padding + status */
  gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X19);
}

static void
gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumArm64Writer * cw)
{
  const guint32 msr_nzcv_x15 = 0xd51b420f;
  gconstpointer request_stack_misalignment = cw->code + 1;

  /* padding + status */
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  if (type == GUM_PROLOG_MINIMAL)
  {
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_LR);

    /* restore status */
    gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);

    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X18, ARM64_REG_X30);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X29, ARM64_REG_X30);

    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q0, ARM64_REG_Q1);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q6, ARM64_REG_Q7);
  }
  else if (type == GUM_PROLOG_FULL)
  {
    /* GumCpuContext.pc + sp */
    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_SP, ARM64_REG_SP, 16);

    /* restore status */
    gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);

    /* GumCpuContext.x[29] + fp + lr + padding */
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X3);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X4, ARM64_REG_X5);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X6, ARM64_REG_X7);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X8, ARM64_REG_X9);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X10, ARM64_REG_X11);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X12, ARM64_REG_X13);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X18, ARM64_REG_X19);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X20, ARM64_REG_X21);

    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19,
        ARM64_REG_X20, ARM64_REG_SP, (5 * 16) + (4 * 32),
        GUM_INDEX_SIGNED_OFFSET);
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_LR);

    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X22, ARM64_REG_X23);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X24, ARM64_REG_X25);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X26, ARM64_REG_X27);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X28, ARM64_REG_X29);

    gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X15, ARM64_REG_SP,
        8);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X30, ARM64_REG_X15);

    /* GumCpuContext.q[128] */
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q0, ARM64_REG_Q1);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q2, ARM64_REG_Q3);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q4, ARM64_REG_Q5);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_Q6, ARM64_REG_Q7);
  }

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X20,
      GUM_ADDRESS (&ctx->pending_stack_misalignment));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_W20, ARM64_REG_X20, 0);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_W20,
      request_stack_misalignment);

  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X19);

  gum_arm64_writer_put_label (cw, request_stack_misalignment);
  gum_arm64_writer_put_brk_imm (cw, 42);
}

static void
gum_exec_ctx_write_stack_push_helper (GumExecCtx * ctx,
                                      GumArm64Writer * cw)
{
  gconstpointer skip_stack_push = cw->code + 1;

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->current_frame));

  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);

  gum_arm64_writer_put_and_reg_reg_imm (cw, ARM64_REG_X2, ARM64_REG_X17,
      ctx->stalker->page_size - 1);
  gum_arm64_writer_put_cbz_reg_label (cw, ARM64_REG_X2, skip_stack_push);

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X0, ARM64_REG_X1,
      ARM64_REG_X17, -((gint) sizeof (GumExecFrame)), GUM_INDEX_PRE_ADJUST);

  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);

  gum_arm64_writer_put_label (cw, skip_stack_push);
  gum_arm64_writer_put_ret (cw);
}

static void
gum_exec_ctx_write_stack_pop_and_go_helper (GumExecCtx * ctx,
                                            GumArm64Writer * cw)
{
  gconstpointer resolve_dynamically = cw->code + 1;

  if ((ctx->stalker->cpu_features & GUM_CPU_PTRAUTH) != 0)
    gum_arm64_writer_put_xpaci_reg (cw, ARM64_REG_X16);

  /*
   * Fast path (try the stack)
   */
  gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X0,
      GUM_ADDRESS (&ctx->current_frame));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X1, ARM64_REG_X0, 0);

  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X1,
      G_STRUCT_OFFSET (GumExecFrame, real_address));
  gum_arm64_writer_put_sub_reg_reg_reg (cw, ARM64_REG_X17, ARM64_REG_X17,
      ARM64_REG_X16);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X17,
      resolve_dynamically);

  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X1,
      G_STRUCT_OFFSET (GumExecFrame, code_address));
  gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X1, ARM64_REG_X1,
      sizeof (GumExecFrame));
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X1, ARM64_REG_X0, 0);

  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X17);

  /*
   * Slow path (resolve dynamically)
   */
  gum_arm64_writer_put_label (cw, resolve_dynamically);

  /* Clear our stack so we might resync later */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X1,
      GUM_ADDRESS (ctx->first_frame));
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X1, ARM64_REG_X0, 0);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X0,
      GUM_ADDRESS (&ctx->return_at));
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X0, 0);

  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 0, GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19, ARM64_REG_LR,
      ARM64_REG_SP, 0, GUM_INDEX_SIGNED_OFFSET);
  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (ctx->last_prolog_minimal));

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X0,
      GUM_ADDRESS (&ctx->return_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X1, ARM64_REG_X0, 0);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (GUM_ENTRYGATE (ret)), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, ARM64_REG_X1);

  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_exec_block_write_exec_generated_code (cw, ctx);
}

static void
gum_exec_ctx_write_invalidator (GumExecCtx * ctx,
                                GumArm64Writer * cw)
{
  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_recompile_and_switch_block), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, ARM64_REG_X17);

  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);

  gum_exec_block_write_exec_generated_code (cw, ctx);
}

static void
gum_exec_ctx_ensure_helper_reachable (GumExecCtx * ctx,
                                      gpointer * helper_ptr,
                                      GumExecHelperWriteFunc write)
{
  GumSlab * slab = &ctx->code_slab->slab;
  GumArm64Writer * cw = &ctx->code_writer;
  gpointer start;

  if (gum_exec_ctx_is_helper_reachable (ctx, helper_ptr))
    return;

  start = gum_slab_cursor (slab);
  gum_stalker_thaw (ctx->stalker, start, gum_slab_available (slab));
  gum_arm64_writer_reset (cw, start);
  *helper_ptr = gum_arm64_writer_cur (cw);

  write (ctx, cw);

  gum_arm64_writer_flush (cw);
  gum_stalker_freeze (ctx->stalker, cw->base, gum_arm64_writer_offset (cw));

  gum_slab_reserve (slab, gum_arm64_writer_offset (cw));
}

static gboolean
gum_exec_ctx_is_helper_reachable (GumExecCtx * ctx,
                                  gpointer * helper_ptr)
{
  GumSlab * slab = &ctx->code_slab->slab;
  GumArm64Writer * cw = &ctx->code_writer;
  GumAddress helper, start, end;

  helper = GUM_ADDRESS (*helper_ptr);
  if (helper == 0)
    return FALSE;

  start = GUM_ADDRESS (gum_slab_start (slab));
  end = GUM_ADDRESS (gum_slab_end (slab));

  if (!gum_arm64_writer_can_branch_directly_between (cw, start, helper))
    return FALSE;

  return gum_arm64_writer_can_branch_directly_between (cw, end, helper);
}

static void
gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
                                               const GumBranchTarget * target,
                                               GumGeneratorContext * gc)
{
  GumArm64Writer * cw = gc->code_writer;

  if (target->reg == ARM64_REG_INVALID)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X15,
        GUM_ADDRESS (target->absolute_address));
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X15);
  }
  else
  {
    gum_exec_ctx_load_real_register_into (ctx, ARM64_REG_X15, target->reg, gc);
    if ((ctx->stalker->cpu_features & GUM_CPU_PTRAUTH) != 0)
      gum_arm64_writer_put_xpaci_reg (cw, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X15);
  }
}

static void
gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                      arm64_reg target_register,
                                      arm64_reg source_register,
                                      GumGeneratorContext * gc)
{
  if (gc->opened_prolog == GUM_PROLOG_MINIMAL)
  {
    gum_exec_ctx_load_real_register_from_minimal_frame_into (ctx,
        target_register, source_register, gc);
    return;
  }
  else if (gc->opened_prolog == GUM_PROLOG_FULL)
  {
    gum_exec_ctx_load_real_register_from_full_frame_into (ctx, target_register,
        source_register, gc);
    return;
  }

  g_assert_not_reached ();
}

static void
gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx,
    arm64_reg target_register,
    arm64_reg source_register,
    GumGeneratorContext * gc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  if (source_register >= ARM64_REG_X0 && source_register <= ARM64_REG_X18)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        (source_register - ARM64_REG_X0) * 8);
  }
  else if (source_register == ARM64_REG_X19 || source_register == ARM64_REG_X20)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        (11 * 16) + (4 * 32) + ((source_register - ARM64_REG_X19) * 8));
  }
  else if (source_register == ARM64_REG_X29 || source_register == ARM64_REG_X30)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        (10 * 16) + ((source_register - ARM64_REG_X29) * 8));
  }
  else
  {
    gum_arm64_writer_put_mov_reg_reg (cw, target_register, source_register);
  }
}

static void
gum_exec_ctx_load_real_register_from_full_frame_into (GumExecCtx * ctx,
                                                      arm64_reg target_register,
                                                      arm64_reg source_register,
                                                      GumGeneratorContext * gc)
{
  GumArm64Writer * cw;

  cw = gc->code_writer;

  if (source_register >= ARM64_REG_X0 && source_register <= ARM64_REG_X28)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, x) +
        ((source_register - ARM64_REG_X0) * 8));
  }
  else if (source_register == ARM64_REG_X29)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, fp));
  }
  else if (source_register == ARM64_REG_X30)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else
  {
    gum_arm64_writer_put_mov_reg_reg (cw, target_register, source_register);
  }
}

static gboolean
gum_exec_ctx_try_handle_exception (GumExecCtx * ctx,
                                   GumExceptionDetails * details)
{
  GumCpuContext * cpu_context = &details->context;
  const guint32 * insn;

  insn = GSIZE_TO_POINTER (cpu_context->pc);

  if (!gum_exec_ctx_contains (ctx, insn))
    return FALSE;

  switch (*insn)
  {
    case 0xa9b77bf3: /* stp x19, lr, [sp, #-(16 + GUM_RED_ZONE_SIZE)]! */
      return gum_exec_ctx_try_handle_misaligned_stack_in_prolog (ctx,
          cpu_context);
    case 0xd4200540: /* brk #42 */
      return gum_exec_ctx_try_handle_misaligned_stack_in_epilog (ctx,
          cpu_context);
    case 0xa9b747f0: /* stp x16, x17, [sp, #-(16 + GUM_RED_ZONE_SIZE)]! */
      return gum_exec_ctx_try_handle_misaligned_stack_in_transition (ctx,
          cpu_context);
    default:
      break;
  }

  return FALSE;
}

static gboolean
gum_exec_ctx_try_handle_misaligned_stack_in_prolog (GumExecCtx * ctx,
                                                    GumCpuContext * cpu_context)
{
  if (cpu_context->sp % GUM_STACK_ALIGNMENT == 0)
    return FALSE;

  gum_exec_ctx_align_stack_temporarily (ctx, cpu_context);

  return TRUE;
}

static gboolean
gum_exec_ctx_try_handle_misaligned_stack_in_epilog (GumExecCtx * ctx,
                                                    GumCpuContext * cpu_context)
{
  guint64 * saved_regs;

  if (ctx->pending_stack_misalignment == 0)
    return FALSE;

  /* Jump back from epilog helper, skipping the ldp instruction */
  cpu_context->pc = cpu_context->x[19] + sizeof (guint32);

  /* Emulate: ldp x19, x20, [sp], #(16 + GUM_RED_ZONE_SIZE) */
  saved_regs = GSIZE_TO_POINTER (cpu_context->sp);
  cpu_context->x[19] = saved_regs[0];
  cpu_context->x[20] = saved_regs[1];
  cpu_context->sp += 16 + GUM_RED_ZONE_SIZE;

  gum_exec_ctx_undo_temporary_stack_alignment (ctx, cpu_context);

  return TRUE;
}

static gboolean
gum_exec_ctx_try_handle_misaligned_stack_in_transition (
    GumExecCtx * ctx,
    GumCpuContext * cpu_context)
{
  const guint32 * insn = GSIZE_TO_POINTER (cpu_context->pc);
  gboolean starts_with_mov_x16, ic_with_existing_prolog;

  if (cpu_context->sp % GUM_STACK_ALIGNMENT == 0)
    return FALSE;

  if (gum_is_ldr_x16_pcrel (insn[1]))
  {
    gum_exec_ctx_handle_misaligned_stack_in_exec_generated_code (ctx,
        cpu_context);
    return TRUE;
  }

  if (((starts_with_mov_x16 = gum_is_mov_x16_reg (insn[1])) &&
      gum_is_b_imm (insn[2])) || gum_is_b_imm (insn[1]))
  {
    gum_exec_ctx_handle_misaligned_stack_in_ret_transfer_code (ctx, cpu_context,
        starts_with_mov_x16 ? &insn[1] : NULL);
    return TRUE;
  }

  if ((ic_with_existing_prolog = gum_is_mov_reg_reg (insn[1])) ||
      insn[1] == 0xa9bf07e0) /* stp x0, x1, [sp, -0x10]! */
  {
    if (ic_with_existing_prolog)
    {
      guint dst_reg_index = insn[1] & GUM_INT5_MASK;
      if (dst_reg_index != 16 && dst_reg_index != 30)
        return FALSE;
    }

    if (ic_with_existing_prolog ||
        insn[2] == 0xa9bf7be2 /* stp x2, lr, [sp, #-0x10]! */)
    {
      gum_exec_ctx_handle_misaligned_stack_in_call_invoke_ic (ctx, cpu_context);
      return TRUE;
    }

    gum_exec_ctx_handle_misaligned_stack_in_jmp_transfer_ic (ctx, cpu_context);
    return TRUE;
  }

  return FALSE;
}

static void
gum_exec_ctx_handle_misaligned_stack_in_exec_generated_code (
    GumExecCtx * ctx,
    GumCpuContext * cpu_context)
{
  gum_exec_ctx_set_program_counter_to_naked_resume_address (ctx, cpu_context);
}

static void
gum_exec_ctx_handle_misaligned_stack_in_jmp_transfer_ic (
    GumExecCtx * ctx,
    GumCpuContext * cpu_context)
{
  const guint32 * insn = GSIZE_TO_POINTER (cpu_context->pc);
  guint num_pop_x0_x1_found;
  const guint32 * cursor;
  gconstpointer prolog_start;

  num_pop_x0_x1_found = 0;
  for (cursor = insn + 1; num_pop_x0_x1_found != 2; cursor++)
  {
    if (*cursor == 0xa8c107e0)
      num_pop_x0_x1_found++;
  }

  prolog_start = cursor + 1 + (4 * 2) + 2;
  cpu_context->pc = GPOINTER_TO_SIZE (prolog_start);

  gum_exec_ctx_align_stack_temporarily (ctx, cpu_context);
}

static void
gum_exec_ctx_handle_misaligned_stack_in_call_invoke_ic (
    GumExecCtx * ctx,
    GumCpuContext * cpu_context)
{
  const guint32 * insn = GSIZE_TO_POINTER (cpu_context->pc);
  gboolean jump_across_ic_entries_found;
  const guint32 * cursor;
  gconstpointer prolog_start;

  jump_across_ic_entries_found = FALSE;
  for (cursor = insn + 2; !jump_across_ic_entries_found; cursor++)
  {
    if (*cursor == 0x14000009)
      jump_across_ic_entries_found = TRUE;
  }

  prolog_start = cursor + (4 * 2) + 3;
  cpu_context->pc = GPOINTER_TO_SIZE (prolog_start);

  gum_exec_ctx_align_stack_temporarily (ctx, cpu_context);
}

static void
gum_exec_ctx_handle_misaligned_stack_in_ret_transfer_code (
    GumExecCtx * ctx,
    GumCpuContext * cpu_context,
    const guint32 * mov_instruction)
{
  guint ret_reg_index = (mov_instruction != NULL)
      ? (*mov_instruction >> 16) & GUM_INT5_MASK
      : 30;

  ctx->return_at = GSIZE_TO_POINTER (cpu_context->x[ret_reg_index]);
  gum_exec_ctx_switch_block (ctx, ctx->return_at);
  gum_exec_ctx_set_program_counter_to_naked_resume_address (ctx, cpu_context);
}

static void
gum_exec_ctx_align_stack_temporarily (GumExecCtx * ctx,
                                      GumCpuContext * cpu_context)
{
  guint misalignment_offset = cpu_context->sp % GUM_STACK_ALIGNMENT;
  g_assert (misalignment_offset != 0);

  cpu_context->sp -= misalignment_offset;
  ctx->pending_stack_misalignment = misalignment_offset;
}

static void
gum_exec_ctx_undo_temporary_stack_alignment (GumExecCtx * ctx,
                                             GumCpuContext * cpu_context)
{
  g_assert (ctx->pending_stack_misalignment != 0);

  cpu_context->sp += ctx->pending_stack_misalignment;
  ctx->pending_stack_misalignment = 0;
}

static void
gum_exec_ctx_set_program_counter_to_naked_resume_address (
    GumExecCtx * ctx,
    GumCpuContext * cpu_context)
{
  gboolean target_is_stalker_generated_block;

  cpu_context->pc = GPOINTER_TO_SIZE (ctx->resume_at);

  target_is_stalker_generated_block = ctx->current_block != NULL;
  if (target_is_stalker_generated_block)
    cpu_context->pc += sizeof (guint32);
}

static GumExecBlock *
gum_exec_block_new (GumExecCtx * ctx)
{
  GumExecBlock * block;
  GumStalker * stalker = ctx->stalker;
  GumCodeSlab * code_slab = ctx->code_slab;
  GumDataSlab * data_slab = ctx->data_slab;
  gsize code_available;

  code_available = gum_slab_available (&code_slab->slab);
  if (code_available < GUM_EXEC_BLOCK_MIN_CAPACITY)
  {
    GumAddressSpec data_spec;

    code_slab = gum_exec_ctx_add_code_slab (ctx, gum_code_slab_new (ctx));

    gum_exec_ctx_compute_data_address_spec (ctx, data_slab->slab.size,
        &data_spec);
    if (!gum_address_spec_is_satisfied_by (&data_spec,
            gum_slab_start (&data_slab->slab)))
    {
      data_slab = gum_exec_ctx_add_data_slab (ctx, gum_data_slab_new (ctx));
    }

    gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

    code_available = gum_slab_available (&code_slab->slab);
  }

  block = gum_slab_try_reserve (&data_slab->slab, sizeof (GumExecBlock));
  if (block == NULL)
  {
    data_slab = gum_exec_ctx_add_data_slab (ctx, gum_data_slab_new (ctx));
    block = gum_slab_reserve (&data_slab->slab, sizeof (GumExecBlock));
  }

  block->ctx = ctx;
  block->code_slab = code_slab;

  block->code_start = gum_slab_cursor (&code_slab->slab);

  gum_stalker_thaw (stalker, block->code_start, code_available);

  return block;
}

static void
gum_exec_block_clear (GumExecBlock * block)
{
  GumCalloutEntry * entry;

  for (entry = gum_exec_block_get_last_callout_entry (block);
      entry != NULL;
      entry = entry->next)
  {
    if (entry->data_destroy != NULL)
      entry->data_destroy (entry->data);
  }
  block->last_callout_offset = 0;

  block->storage_block = NULL;
}

static gconstpointer
gum_exec_block_check_address_for_exclusion (GumExecBlock * block,
                                            gconstpointer address)
{
  GumExecCtx * ctx = block->ctx;

  if (ctx->activation_target != NULL)
    return address;

  if (gum_stalker_is_excluding (ctx->stalker, address))
    return NULL;

  return address;
}

static void
gum_exec_block_commit (GumExecBlock * block)
{
  GumStalker * stalker = block->ctx->stalker;
  gsize snapshot_size;

  snapshot_size =
      gum_stalker_snapshot_space_needed_for (stalker, block->real_size);
  memcpy (gum_exec_block_get_snapshot_start (block), block->real_start,
      snapshot_size);

  block->capacity = block->code_size + snapshot_size;

  gum_slab_reserve (&block->code_slab->slab, block->capacity);

  gum_stalker_freeze (stalker, block->code_start, block->code_size);
}

static void
gum_exec_block_invalidate (GumExecBlock * block)
{
  GumExecCtx * ctx = block->ctx;
  GumStalker * stalker = ctx->stalker;
  GumArm64Writer * cw = &ctx->code_writer;
  const gsize max_size = GUM_INVALIDATE_TRAMPOLINE_MAX_SIZE;
  gconstpointer already_saved = cw->code + 1;

  gum_stalker_thaw (stalker, block->code_start, max_size);
  gum_arm64_writer_reset (cw, block->code_start);

  gum_arm64_writer_put_b_label (cw, already_saved);
  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE), GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_label (cw, already_saved);
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X17, GUM_ADDRESS (block));
  gum_arm64_writer_put_b_imm (cw, GUM_ADDRESS (block->code_slab->invalidator));

  gum_arm64_writer_flush (cw);
  g_assert (gum_arm64_writer_offset (cw) <= max_size);
  gum_stalker_freeze (stalker, block->code_start, max_size);
}

static gpointer
gum_exec_block_get_snapshot_start (GumExecBlock * block)
{
  return block->code_start + block->code_size;
}

static GumCalloutEntry *
gum_exec_block_get_last_callout_entry (const GumExecBlock * block)
{
  const guint last_callout_offset = block->last_callout_offset;

  if (last_callout_offset == 0)
    return NULL;

  return (GumCalloutEntry *) (block->code_start + last_callout_offset);
}

static void
gum_exec_block_set_last_callout_entry (GumExecBlock * block,
                                       GumCalloutEntry * entry)
{
  block->last_callout_offset = (guint8 *) entry - block->code_start;
}

static void
gum_exec_block_backpatch_call (GumExecBlock * block,
                               gpointer code_start,
                               GumPrologType opened_prolog,
                               gpointer target_address,
                               gpointer ret_real_address,
                               gpointer ret_code_address)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;

  if (gum_exec_ctx_may_now_backpatch (ctx, block))
  {
    GumStalker * stalker = ctx->stalker;
    GumArm64Writer * cw = &ctx->code_writer;
    const gsize code_max_size = ret_code_address - code_start;

    gum_spinlock_acquire (&ctx->code_lock);

    gum_stalker_thaw (stalker, code_start, code_max_size);
    gum_arm64_writer_reset (cw, code_start);

    if (opened_prolog == GUM_PROLOG_NONE)
    {
      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
          ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
          GUM_INDEX_PRE_ADJUST);
      gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
      gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X2, ARM64_REG_LR);
    }

    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X0,
        GUM_ADDRESS (ret_real_address));
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X1,
        GUM_ADDRESS (ret_code_address));
    gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (block->ctx->last_stack_push));

    if (opened_prolog == GUM_PROLOG_NONE)
    {
      gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X2, ARM64_REG_LR);
      gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
      gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
          ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
          GUM_INDEX_POST_ADJUST);
    }
    else
    {
      gum_exec_ctx_write_epilog (block->ctx, opened_prolog, cw);
    }

    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_LR,
        GUM_ADDRESS (ret_real_address));

    gum_exec_block_write_jmp_to_block_start (block, target_address);

    gum_arm64_writer_flush (cw);
    g_assert (gum_arm64_writer_offset (cw) <= code_max_size);
    gum_stalker_freeze (stalker, code_start, code_max_size);

    gum_spinlock_release (&ctx->code_lock);
  }
}

static void
gum_exec_block_backpatch_jmp (GumExecBlock * block,
                              gpointer code_start,
                              GumPrologType opened_prolog,
                              gpointer target_address)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;

  if (gum_exec_ctx_may_now_backpatch (ctx, block))
  {
    GumStalker * stalker = ctx->stalker;
    GumArm64Writer * cw = &ctx->code_writer;
    const gsize code_max_size = 128;

    gum_spinlock_acquire (&ctx->code_lock);

    gum_stalker_thaw (stalker, code_start, code_max_size);
    gum_arm64_writer_reset (cw, code_start);

    if (opened_prolog != GUM_PROLOG_NONE)
    {
      gum_exec_ctx_write_epilog (block->ctx, opened_prolog, cw);
    }

    gum_exec_block_write_jmp_to_block_start (block, target_address);

    gum_arm64_writer_flush (cw);
    g_assert (gum_arm64_writer_offset (cw) <= code_max_size);
    gum_stalker_freeze (stalker, code_start, code_max_size);

    gum_spinlock_release (&ctx->code_lock);
  }
}

static void
gum_exec_block_backpatch_ret (GumExecBlock * block,
                              gpointer code_start,
                              gpointer target_address)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;

  if (gum_exec_ctx_may_now_backpatch (ctx, block))
  {
    GumStalker * stalker = ctx->stalker;
    GumArm64Writer * cw = &ctx->code_writer;
    const gsize code_max_size = 128;

    gum_spinlock_acquire (&ctx->code_lock);

    gum_stalker_thaw (stalker, code_start, code_max_size);
    gum_arm64_writer_reset (cw, code_start);

    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
        GUM_INDEX_POST_ADJUST);

    gum_exec_block_write_jmp_to_block_start (block, target_address);

    gum_arm64_writer_flush (cw);
    g_assert (gum_arm64_writer_offset (cw) <= code_max_size);
    gum_stalker_freeze (stalker, code_start, code_max_size);

    gum_spinlock_release (&ctx->code_lock);
  }
}

static void
gum_exec_block_backpatch_inline_cache (GumExecBlock * block,
                                       gpointer * ic_entries)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;

  if (gum_exec_ctx_may_now_backpatch (ctx, block))
  {
    guint offset = (ic_entries[0] == NULL) ? 0 : 2;

    if (ic_entries[offset + 0] == NULL)
    {
      GumStalker * stalker = ctx->stalker;
      const gsize ic_slot_size = 2 * sizeof (gpointer);

      gum_spinlock_acquire (&ctx->code_lock);

      gum_stalker_thaw (stalker, ic_entries + offset, ic_slot_size);

      ic_entries[offset + 0] = block->real_start;
      ic_entries[offset + 1] = block->code_start;

      gum_stalker_freeze (stalker, ic_entries + offset, ic_slot_size);

      gum_spinlock_release (&ctx->code_lock);
    }
  }
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_branch_insn (GumExecBlock * block,
                                       GumGeneratorContext * gc)
{
  GumExecCtx * ctx = block->ctx;
  GumInstruction * insn = gc->instruction;
  const guint id = insn->ci->id;
  GumArm64Writer * cw = gc->code_writer;
  cs_arm64 * arm64 = &insn->ci->detail->arm64;
  cs_arm64_op * op = &arm64->operands[0];
  cs_arm64_op * op2 = NULL;
  cs_arm64_op * op3 = NULL;
  arm64_cc cc = arm64->cc;
  gboolean is_conditional;
  GumBranchTarget target = { 0, };

  g_assert (arm64->op_count != 0);

  is_conditional = (id == ARM64_INS_B && cc != ARM64_CC_INVALID) ||
      (id == ARM64_INS_CBZ) || (id == ARM64_INS_CBNZ) ||
      (id == ARM64_INS_TBZ) || (id == ARM64_INS_TBNZ);

  target.origin_ip = insn->end;

  switch (id)
  {
    case ARM64_INS_B:
    case ARM64_INS_BL:
      g_assert (op->type == ARM64_OP_IMM);

      target.absolute_address = GSIZE_TO_POINTER (op->imm);
      target.reg = ARM64_REG_INVALID;

      break;
    case ARM64_INS_BR:
    case ARM64_INS_BRAA:
    case ARM64_INS_BRAAZ:
    case ARM64_INS_BRAB:
    case ARM64_INS_BRABZ:
    case ARM64_INS_BLR:
    case ARM64_INS_BLRAA:
    case ARM64_INS_BLRAAZ:
    case ARM64_INS_BLRAB:
    case ARM64_INS_BLRABZ:
      g_assert (op->type == ARM64_OP_REG);

      target.reg = op->reg;

      break;
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
      op2 = &arm64->operands[1];

      g_assert (op->type == ARM64_OP_REG);
      g_assert (op2->type == ARM64_OP_IMM);

      target.absolute_address = GSIZE_TO_POINTER (op2->imm);
      target.reg = ARM64_REG_INVALID;

      break;
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
      op2 = &arm64->operands[1];
      op3 = &arm64->operands[2];

      g_assert (op->type == ARM64_OP_REG);
      g_assert (op2->type == ARM64_OP_IMM);
      g_assert (op3->type == ARM64_OP_IMM);

      target.absolute_address = GSIZE_TO_POINTER (op3->imm);
      target.reg = ARM64_REG_INVALID;

      break;
    default:
      g_assert_not_reached ();
  }

  switch (id)
  {
    case ARM64_INS_B:
    case ARM64_INS_BR:
    case ARM64_INS_BRAA:
    case ARM64_INS_BRAAZ:
    case ARM64_INS_BRAB:
    case ARM64_INS_BRABZ:
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
    {
      gpointer is_false;
      GumExecCtxReplaceCurrentBlockFunc regular_entry_func, cond_entry_func;

      gum_arm64_relocator_skip_one (gc->relocator);

      is_false =
          GUINT_TO_POINTER ((GPOINTER_TO_UINT (insn->start) << 16) | 0xbeef);

      if (is_conditional)
      {
        gum_exec_block_close_prolog (block, gc);

        regular_entry_func = NULL;

        /* jump to is_false if is_false */
        switch (id)
        {
          case ARM64_INS_B:
          {
            arm64_cc not_cc;

            g_assert (cc != ARM64_CC_INVALID);
            g_assert (cc > ARM64_CC_INVALID);
            g_assert (cc <= ARM64_CC_NV);

            not_cc = cc + 2 * (cc % 2) - 1;
            gum_arm64_writer_put_b_cond_label (cw, not_cc, is_false);

            cond_entry_func = GUM_ENTRYGATE (jmp_cond_cc);

            break;
          }
          case ARM64_INS_CBZ:
            gum_arm64_writer_put_cbnz_reg_label (cw, op->reg, is_false);
            cond_entry_func = GUM_ENTRYGATE (jmp_cond_cbz);
            break;
          case ARM64_INS_CBNZ:
            gum_arm64_writer_put_cbz_reg_label (cw, op->reg, is_false);
            cond_entry_func = GUM_ENTRYGATE (jmp_cond_cbnz);
            break;
          case ARM64_INS_TBZ:
            gum_arm64_writer_put_tbnz_reg_imm_label (cw, op->reg, op2->imm,
                is_false);
            cond_entry_func = GUM_ENTRYGATE (jmp_cond_tbz);
            break;
          case ARM64_INS_TBNZ:
            gum_arm64_writer_put_tbz_reg_imm_label (cw, op->reg, op2->imm,
                is_false);
            cond_entry_func = GUM_ENTRYGATE (jmp_cond_tbnz);
            break;
          default:
            cond_entry_func = NULL;
            g_assert_not_reached ();
        }
      }
      else
      {
        if (target.reg != ARM64_REG_INVALID)
          regular_entry_func = GUM_ENTRYGATE (jmp_reg);
        else
          regular_entry_func = GUM_ENTRYGATE (jmp_imm);
        cond_entry_func = NULL;
      }

      gum_exec_block_write_jmp_transfer_code (block, &target,
          is_conditional ? cond_entry_func : regular_entry_func, gc);

      if (is_conditional)
      {
        GumBranchTarget cond_target = { 0, };

        cond_target.absolute_address = insn->end;
        cond_target.reg = ARM64_REG_INVALID;

        gum_arm64_writer_put_label (cw, is_false);

        if (gc->exclusive_load_offset == GUM_INSTRUCTION_OFFSET_NONE)
        {
          gum_exec_block_write_jmp_transfer_code (block, &cond_target,
              cond_entry_func, gc);
        }
        else
        {
          return GUM_REQUIRE_EXCLUSIVE_STORE;
        }
      }

      break;
    }
    case ARM64_INS_BL:
    case ARM64_INS_BLR:
    case ARM64_INS_BLRAA:
    case ARM64_INS_BLRAAZ:
    case ARM64_INS_BLRAB:
    case ARM64_INS_BLRABZ:
    {
      gboolean target_is_excluded = FALSE;

      if ((ctx->sink_mask & GUM_CALL) != 0)
      {
        gum_exec_block_write_call_event_code (block, &target, gc,
            GUM_CODE_INTERRUPTIBLE);
      }

      if (target.reg == ARM64_REG_INVALID &&
          ctx->activation_target == NULL)
      {
        target_is_excluded =
            gum_stalker_is_excluding (ctx->stalker, target.absolute_address);
      }

      if (target_is_excluded)
      {
        GumBranchTarget next_instruction = { 0, };

        gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);
        gum_arm64_writer_put_call_address_with_arguments (cw,
            GUM_ADDRESS (gum_exec_ctx_begin_call), 2,
            GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
            GUM_ARG_ADDRESS, GUM_ADDRESS (insn->end));
        gum_exec_block_close_prolog (block, gc);

        gum_arm64_relocator_write_one (gc->relocator);

        gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);
        gum_arm64_writer_put_call_address_with_arguments (cw,
            GUM_ADDRESS (gum_exec_ctx_end_call), 1,
            GUM_ARG_ADDRESS, GUM_ADDRESS (ctx));
        gum_exec_block_close_prolog (block, gc);

        next_instruction.absolute_address = insn->end;
        next_instruction.reg = ARM64_REG_INVALID;
        gum_exec_block_write_jmp_transfer_code (block, &next_instruction,
            GUM_ENTRYGATE (excluded_call_imm), gc);

        return GUM_REQUIRE_NOTHING;
      }

      gum_arm64_relocator_skip_one (gc->relocator);
      gum_exec_block_write_call_invoke_code (block, &target, gc);

      break;
    }
    default:
      g_assert_not_reached ();
  }

  return GUM_REQUIRE_NOTHING;
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_ret_insn (GumExecBlock * block,
                                    GumGeneratorContext * gc)
{
  GumInstruction * insn;
  cs_arm64 * arm64;
  cs_arm64_op * op;
  arm64_reg ret_reg;

  if ((block->ctx->sink_mask & GUM_RET) != 0)
    gum_exec_block_write_ret_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);

  insn = gc->instruction;
  arm64 = &insn->ci->detail->arm64;

  if (arm64->op_count == 0)
  {
    ret_reg = ARM64_REG_X30;
  }
  else
  {
    g_assert (arm64->op_count == 1);

    op = &arm64->operands[0];
    g_assert (op->type == ARM64_OP_REG);

    ret_reg = op->reg;
  }
  gum_arm64_relocator_skip_one (gc->relocator);
  gum_exec_block_write_ret_transfer_code (block, gc, ret_reg);

  return GUM_REQUIRE_NOTHING;
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_sysenter_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
#ifdef HAVE_LINUX
  return gum_exec_block_virtualize_linux_sysenter (block, gc);
#else
  return GUM_REQUIRE_RELOCATION;
#endif
}

#ifdef HAVE_LINUX

static GumVirtualizationRequirements
gum_exec_block_virtualize_linux_sysenter (GumExecBlock * block,
                                          GumGeneratorContext * gc)
{
  GumArm64Writer * cw = gc->code_writer;
  const cs_insn * insn = gc->instruction->ci;
  gconstpointer perform_regular_syscall = cw->code + 1;
  gconstpointer perform_next_instruction = cw->code + 2;
  const guint32 mrs_x15_nzcv = 0xd53b420f;
  const guint32 msr_nzcv_x15 = 0xd51b420f;

  gum_arm64_relocator_skip_one (gc->relocator);

  if (gc->opened_prolog != GUM_PROLOG_NONE)
    gum_exec_block_close_prolog (block, gc);

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X15, ARM64_REG_X17,
      ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE), GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_instruction (cw, mrs_x15_nzcv);

  gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_X17,
      ARM64_REG_X8, __NR_clone);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X17,
      perform_regular_syscall);

  gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X15,
      ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
  gum_arm64_writer_put_bytes (cw, insn->bytes, 4);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X0,
      perform_next_instruction);

  /*
   * We are on the child return to the original next instruction
   *
   * TODO: Is there any way we can avoid clobbering X17 here?
   */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X17,
      GUM_ADDRESS (gc->instruction->start + GUM_RESTORATION_PROLOG_SIZE));
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X17);

  gum_arm64_writer_put_label (cw, perform_regular_syscall);
  gum_arm64_writer_put_instruction (cw, msr_nzcv_x15);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X15,
      ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
  gum_arm64_writer_put_bytes (cw, insn->bytes, 4);

  gum_arm64_writer_put_label (cw, perform_next_instruction);

  return GUM_REQUIRE_NOTHING;
}

#endif

static void
gum_exec_block_write_call_invoke_code (GumExecBlock * block,
                                       const GumBranchTarget * target,
                                       GumGeneratorContext * gc)
{
  GumExecCtx * ctx = block->ctx;
  GumStalker * stalker = ctx->stalker;
  const gint trust_threshold = stalker->trust_threshold;
  GumArm64Writer * cw = gc->code_writer;
  const GumAddress call_code_start = cw->pc;
  const GumPrologType opened_prolog = gc->opened_prolog;
  gboolean can_backpatch_statically;
  guint ic_push_real_address_ref = 0;
  guint ic_push_code_address_ref = 0;
  guint ic_load_real_address_ref = 0;
  gpointer * ic_entries = NULL;
  GumPrologType second_prolog;
  GumExecCtxReplaceCurrentBlockFunc entry_func;
  gconstpointer perform_stack_push = cw->code + 1;
  gconstpointer try_second = cw->code + 2;
  gconstpointer jump_to_cached = cw->code + 3;
  gconstpointer resolve_dynamically = cw->code + 4;
  gconstpointer keep_this_blr = cw->code + 5;
  GumAddress ret_real_address, ret_code_address;

  can_backpatch_statically =
      trust_threshold >= 0 &&
      target->reg == ARM64_REG_INVALID;

  if (trust_threshold >= 0 && !can_backpatch_statically)
  {
    arm64_reg call_target_reg, candidate_reg;
    guint ic1_real_ref, ic1_code_ref;
    guint ic2_real_ref, ic2_code_ref;

    if (opened_prolog == GUM_PROLOG_NONE)
    {
      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
          ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
          GUM_INDEX_PRE_ADJUST);
      gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
      gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X2, ARM64_REG_LR);
    }

    ic_push_real_address_ref =
        gum_arm64_writer_put_ldr_reg_ref (cw, ARM64_REG_X0);
    ic_push_code_address_ref =
        gum_arm64_writer_put_ldr_reg_ref (cw, ARM64_REG_X1);
    gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (ctx->last_stack_push));

    if (opened_prolog == GUM_PROLOG_NONE)
    {
      gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X2, ARM64_REG_LR);
      gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
      gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
          ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
          GUM_INDEX_POST_ADJUST);
    }
    else
    {
      gum_exec_block_close_prolog (block, gc);
    }

    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
        GUM_INDEX_PRE_ADJUST);

    if (target->reg != ARM64_REG_LR)
    {
      call_target_reg = ARM64_REG_LR;
      candidate_reg = (target->reg != ARM64_REG_X16)
          ? ARM64_REG_X16
          : ARM64_REG_X17;
    }
    else
    {
      call_target_reg = ARM64_REG_X16;
      candidate_reg = ARM64_REG_X17;
    }

    gum_arm64_writer_put_mov_reg_reg (cw, call_target_reg, target->reg);
    if ((stalker->cpu_features & GUM_CPU_PTRAUTH) != 0)
      gum_arm64_writer_put_xpaci_reg (cw, call_target_reg);

    ic1_real_ref = gum_arm64_writer_put_ldr_reg_ref (cw, candidate_reg);
    gum_arm64_writer_put_sub_reg_reg_reg (cw, candidate_reg, candidate_reg,
        call_target_reg);
    gum_arm64_writer_put_cbnz_reg_label (cw, candidate_reg, try_second);
    ic1_code_ref = gum_arm64_writer_put_ldr_reg_ref (cw, candidate_reg);
    gum_arm64_writer_put_b_label (cw, jump_to_cached);

    gum_arm64_writer_put_label (cw, try_second);
    ic2_real_ref = gum_arm64_writer_put_ldr_reg_ref (cw, candidate_reg);
    gum_arm64_writer_put_sub_reg_reg_reg (cw, candidate_reg, candidate_reg,
        call_target_reg);
    gum_arm64_writer_put_cbnz_reg_label (cw, candidate_reg,
        resolve_dynamically);
    ic2_code_ref = gum_arm64_writer_put_ldr_reg_ref (cw, candidate_reg);
    gum_arm64_writer_put_b_label (cw, jump_to_cached);

    ic_entries = gum_arm64_writer_cur (cw);
    gum_arm64_writer_put_ldr_reg_value (cw, ic1_real_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic1_code_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic2_real_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic2_code_ref, 0);

    gum_arm64_writer_put_label (cw, jump_to_cached);
    ic_load_real_address_ref =
        gum_arm64_writer_put_ldr_reg_ref (cw, ARM64_REG_LR);
    gum_arm64_writer_put_br_reg_no_auth (cw, candidate_reg);

    gum_arm64_writer_put_label (cw, resolve_dynamically);
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
        GUM_INDEX_POST_ADJUST);
  }

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);
  second_prolog = gc->opened_prolog;

  gum_exec_ctx_write_push_branch_target_address (ctx, target, gc);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  if (target->reg != ARM64_REG_INVALID)
  {
    entry_func = GUM_ENTRYGATE (call_reg);

    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_check_address_for_exclusion), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_REGISTER, ARM64_REG_X15);

    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X0);
    gum_arm64_writer_put_cbz_reg_label (cw, ARM64_REG_X15, keep_this_blr);
  }
  else
  {
    entry_func = GUM_ENTRYGATE (call_imm);
  }

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (entry_func), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, ARM64_REG_X15);
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X3, ARM64_REG_X0);
  gum_arm64_writer_put_b_label (cw, perform_stack_push);

  if (can_backpatch_statically)
  {
    guint i;

    /*
     * We need some padding so the backpatching doesn't overwrite the return
     * handling logic below
     */
    for (i = 0; i != 10; i++)
      gum_arm64_writer_put_brk_imm (cw, 15);
  }

  ret_real_address = GUM_ADDRESS (gc->instruction->end);
  ret_code_address = cw->pc;

  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);

  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (GUM_ENTRYGATE (post_call_invoke)), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, ret_real_address);

  if (trust_threshold >= 0)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X3,
        GUM_ADDRESS (&ctx->current_block));
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X3, ARM64_REG_X3, 0);
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_ret), 3,
        GUM_ARG_REGISTER, ARM64_REG_X3,
        GUM_ARG_ADDRESS, ret_code_address,
        GUM_ARG_REGISTER, ARM64_REG_X0);
  }

  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);
  gum_exec_block_write_exec_generated_code (cw, ctx);

  gum_arm64_writer_put_label (cw, perform_stack_push);
  if (ic_entries == NULL)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X0, ret_real_address);
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X1, ret_code_address);
    gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (ctx->last_stack_push));
  }

  if (trust_threshold >= 0)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X6,
        GUM_ADDRESS (&ctx->current_block));
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X6, ARM64_REG_X6, 0);
  }

  if (can_backpatch_statically)
  {
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_call), 6,
        GUM_ARG_REGISTER, ARM64_REG_X6,
        GUM_ARG_ADDRESS, call_code_start,
        GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog),
        GUM_ARG_REGISTER, ARM64_REG_X3,
        GUM_ARG_ADDRESS, ret_real_address,
        GUM_ARG_ADDRESS, ret_code_address);
  }

  if (ic_entries != NULL)
  {
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 2,
        GUM_ARG_REGISTER, ARM64_REG_X6,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ic_entries));
  }

  gum_exec_block_close_prolog (block, gc);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_LR, ret_real_address);

  gum_exec_block_write_exec_generated_code (cw, ctx);

  if (ic_entries != NULL)
  {
    gum_arm64_writer_put_ldr_reg_value (cw, ic_push_real_address_ref,
        ret_real_address);
    gum_arm64_writer_put_ldr_reg_value (cw, ic_push_code_address_ref,
        ret_code_address);
    gum_arm64_writer_put_ldr_reg_value (cw, ic_load_real_address_ref,
        ret_real_address);
  }

  if (target->reg != ARM64_REG_INVALID)
  {
    GumInstruction * insn = gc->instruction;
    GumBranchTarget next_insn_as_target = { 0, };
    next_insn_as_target.absolute_address = insn->end;
    next_insn_as_target.reg = ARM64_REG_INVALID;

    gum_arm64_writer_put_label (cw, keep_this_blr);

    gc->opened_prolog = second_prolog;

    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_begin_call), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
        GUM_ARG_ADDRESS, GUM_ADDRESS (insn->end));
    gum_exec_block_close_prolog (block, gc);

    if (gc->instruction->ci->id == ARM64_INS_BLR)
      gum_arm64_writer_put_blr_reg_no_auth (cw, target->reg);
    else
      gum_arm64_writer_put_blr_reg (cw, target->reg);

    gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_end_call), 1,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ctx));
    gum_exec_block_write_jmp_transfer_code (block, &next_insn_as_target,
        GUM_ENTRYGATE (excluded_call_reg), gc);
  }
}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        GumExecCtxReplaceCurrentBlockFunc func,
                                        GumGeneratorContext * gc)
{
  GumStalker * stalker = block->ctx->stalker;
  const gint trust_threshold = stalker->trust_threshold;
  GumArm64Writer * cw = gc->code_writer;
  const GumAddress code_start = cw->pc;
  const GumPrologType opened_prolog = gc->opened_prolog;
  gboolean can_backpatch_statically;
  gpointer * ic_entries = NULL;

  can_backpatch_statically =
      trust_threshold >= 0 &&
      target->reg == ARM64_REG_INVALID;

  if (trust_threshold >= 0 && !can_backpatch_statically)
  {
    gconstpointer try_second = cw->code + 1;
    gconstpointer resolve_dynamically = cw->code + 2;
    arm64_reg jmp_target_reg, candidate_reg;
    guint ic1_real_ref, ic1_code_ref;
    guint ic2_real_ref, ic2_code_ref;

    if (opened_prolog != GUM_PROLOG_NONE)
      gum_exec_block_close_prolog (block, gc);

    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
        GUM_INDEX_PRE_ADJUST);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);

    if (target->reg != ARM64_REG_X0)
    {
      jmp_target_reg = ARM64_REG_X0;
      candidate_reg = (target->reg != ARM64_REG_X16)
          ? ARM64_REG_X16
          : ARM64_REG_X17;
    }
    else
    {
      jmp_target_reg = ARM64_REG_X1;
      candidate_reg = ARM64_REG_X16;
    }

    gum_arm64_writer_put_mov_reg_reg (cw, jmp_target_reg, target->reg);
    if ((stalker->cpu_features & GUM_CPU_PTRAUTH) != 0)
      gum_arm64_writer_put_xpaci_reg (cw, jmp_target_reg);

    ic1_real_ref = gum_arm64_writer_put_ldr_reg_ref (cw, candidate_reg);
    gum_arm64_writer_put_sub_reg_reg_reg (cw, candidate_reg, candidate_reg,
        jmp_target_reg);
    gum_arm64_writer_put_cbnz_reg_label (cw, candidate_reg, try_second);
    ic1_code_ref = gum_arm64_writer_put_ldr_reg_ref (cw, candidate_reg);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_br_reg_no_auth (cw, candidate_reg);

    gum_arm64_writer_put_label (cw, try_second);
    ic2_real_ref = gum_arm64_writer_put_ldr_reg_ref (cw, candidate_reg);
    gum_arm64_writer_put_sub_reg_reg_reg (cw, candidate_reg, candidate_reg,
        jmp_target_reg);
    gum_arm64_writer_put_cbnz_reg_label (cw, candidate_reg,
        resolve_dynamically);
    ic2_code_ref = gum_arm64_writer_put_ldr_reg_ref (cw, candidate_reg);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_br_reg_no_auth (cw, candidate_reg);

    ic_entries = gum_arm64_writer_cur (cw);
    gum_arm64_writer_put_ldr_reg_value (cw, ic1_real_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic1_code_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic2_real_ref, 0);
    gum_arm64_writer_put_ldr_reg_value (cw, ic2_code_ref, 0);

    gum_arm64_writer_put_label (cw, resolve_dynamically);
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
        GUM_INDEX_POST_ADJUST);
  }

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

  gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (func), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM64_REG_X15);

  if (trust_threshold >= 0)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X4,
        GUM_ADDRESS (&block->ctx->current_block));
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X4, ARM64_REG_X4, 0);
  }

  if (can_backpatch_statically)
  {
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_jmp), 4,
        GUM_ARG_REGISTER, ARM64_REG_X4,
        GUM_ARG_ADDRESS, code_start,
        GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog),
        GUM_ARG_REGISTER, ARM64_REG_X0);
  }

  if (ic_entries != NULL)
  {
    gum_arm64_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 2,
        GUM_ARG_REGISTER, ARM64_REG_X4,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ic_entries));
  }

  gum_exec_block_close_prolog (block, gc);
  gum_exec_block_write_exec_generated_code (cw, block->ctx);
}

static void
gum_exec_block_write_jmp_to_block_start (GumExecBlock * block,
                                         gpointer block_start)
{
  GumArm64Writer * cw = &block->ctx->code_writer;
  const GumAddress address = GUM_ADDRESS (block_start);
  const GumAddress body_address = address + GUM_RESTORATION_PROLOG_SIZE;

  if (gum_arm64_writer_can_branch_directly_between (cw, cw->pc, body_address))
  {
    gum_arm64_writer_put_b_imm (cw, body_address);
  }
  else
  {
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
        GUM_INDEX_PRE_ADJUST);
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16, address);
    gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X16);
  }
}

static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        GumGeneratorContext * gc,
                                        arm64_reg ret_reg)
{
  GumArm64Writer * cw = gc->code_writer;

  gum_exec_block_close_prolog (block, gc);

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
      ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);
  if (ret_reg != ARM64_REG_X16)
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X16, ret_reg);
  gum_arm64_writer_put_b_imm (cw,
      GUM_ADDRESS (block->ctx->last_stack_pop_and_go));
}

static void
gum_exec_block_write_exec_generated_code (GumArm64Writer * cw,
                                          GumExecCtx * ctx)
{
  gconstpointer dont_pop_now = cw->code + 1;

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE), GUM_INDEX_PRE_ADJUST);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->current_block));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X17, dont_pop_now);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);

  gum_arm64_writer_put_label (cw, dont_pop_now);
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X17);
}

static void
gum_exec_block_write_call_event_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc)
{
  GumArm64Writer * cw = gc->code_writer;

  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc);

  gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X14, ARM64_REG_X15);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_emit_call_event), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, ARM64_REG_X14,
      GUM_ARG_REGISTER, ARM64_REG_X20);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_ret_event_code (GumExecBlock * block,
                                     GumGeneratorContext * gc,
                                     GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc);

  gum_exec_ctx_load_real_register_into (block->ctx, ARM64_REG_X14, ARM64_REG_LR,
      gc);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_ret_event), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, ARM64_REG_X14,
      GUM_ARG_REGISTER, ARM64_REG_X20);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_exec_event_code (GumExecBlock * block,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_exec_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, ARM64_REG_X20);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_block_event_code (GumExecBlock * block,
                                       GumGeneratorContext * gc,
                                       GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_block_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM64_REG_X20);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
                                          GumGeneratorContext * gc,
                                          GumCodeContext cc)
{
  GumExecCtx * ctx = block->ctx;
  GumArm64Writer * cw = gc->code_writer;
  gconstpointer beach = cw->code + 1;
  GumPrologType opened_prolog;

  if (cc != GUM_CODE_INTERRUPTIBLE)
    return;

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_maybe_unfollow), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  gum_arm64_writer_put_cbz_reg_label (cw, ARM64_REG_X0, beach);

  opened_prolog = gc->opened_prolog;
  gum_exec_block_close_prolog (block, gc);
  gc->opened_prolog = opened_prolog;

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16,
      0);
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X17);

  gum_arm64_writer_put_label (cw, beach);
}

static void
gum_exec_block_maybe_write_call_probe_code (GumExecBlock * block,
                                            GumGeneratorContext * gc)
{
  GumStalker * stalker = block->ctx->stalker;

  if (!stalker->any_probes_attached)
    return;

  gum_spinlock_acquire (&stalker->probe_lock);

  if (g_hash_table_contains (stalker->probe_array_by_address,
          block->real_start))
  {
    gum_exec_block_write_call_probe_code (block, gc);
  }

  gum_spinlock_release (&stalker->probe_lock);
}

static void
gum_exec_block_write_call_probe_code (GumExecBlock * block,
                                      GumGeneratorContext * gc)
{
  g_assert (gc->opened_prolog == GUM_PROLOG_NONE);
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_block_invoke_call_probes), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM64_REG_X20);
}

static void
gum_exec_block_invoke_call_probes (GumExecBlock * block,
                                   GumCpuContext * cpu_context)
{
  GumStalker * stalker = block->ctx->stalker;
  const gpointer target_address = block->real_start;
  GumCallProbe ** probes_copy;
  guint num_probes, i;
  GumCallDetails d;

  probes_copy = NULL;
  num_probes = 0;
  {
    GPtrArray * probes;

    gum_spinlock_acquire (&stalker->probe_lock);

    probes =
        g_hash_table_lookup (stalker->probe_array_by_address, target_address);
    if (probes != NULL)
    {
      num_probes = probes->len;
      probes_copy = g_newa (GumCallProbe *, num_probes);
      for (i = 0; i != num_probes; i++)
      {
        probes_copy[i] = gum_call_probe_ref (g_ptr_array_index (probes, i));
      }
    }

    gum_spinlock_release (&stalker->probe_lock);
  }
  if (num_probes == 0)
    return;

  d.target_address = target_address;
  d.return_address = GSIZE_TO_POINTER (cpu_context->lr);
  d.stack_data = GSIZE_TO_POINTER (cpu_context->sp);
  d.cpu_context = cpu_context;

  cpu_context->pc = GPOINTER_TO_SIZE (target_address);

  for (i = 0; i != num_probes; i++)
  {
    GumCallProbe * probe = probes_copy[i];

    probe->callback (&d, probe->user_data);

    gum_call_probe_unref (probe);
  }
}

static gpointer
gum_exec_block_write_inline_data (GumArm64Writer * cw,
                                  gconstpointer data,
                                  gsize size,
                                  GumAddress * address)
{
  gpointer location;
  gconstpointer after_data = cw->code + 1;

  g_assert (size % 4 == 0);

  while (gum_arm64_writer_offset (cw) < GUM_INVALIDATE_TRAMPOLINE_MAX_SIZE)
  {
    gum_arm64_writer_put_nop (cw);
  }

  gum_arm64_writer_put_b_label (cw, after_data);

  location = gum_arm64_writer_cur (cw);
  if (address != NULL)
    *address = cw->pc;
  gum_arm64_writer_put_bytes (cw, data, size);

  gum_arm64_writer_put_label (cw, after_data);

  return location;
}

static void
gum_exec_block_open_prolog (GumExecBlock * block,
                            GumPrologType type,
                            GumGeneratorContext * gc)
{
  if (gc->opened_prolog >= type)
    return;

  /* We don't want to handle this case for performance reasons */
  g_assert (gc->opened_prolog == GUM_PROLOG_NONE);

  gc->opened_prolog = type;

  gum_exec_ctx_write_prolog (block->ctx, type, gc->code_writer);
}

static void
gum_exec_block_close_prolog (GumExecBlock * block,
                             GumGeneratorContext * gc)
{
  if (gc->opened_prolog == GUM_PROLOG_NONE)
    return;

  gum_exec_ctx_write_epilog (block->ctx, gc->opened_prolog, gc->code_writer);
  gc->opened_prolog = GUM_PROLOG_NONE;
}

static GumCodeSlab *
gum_code_slab_new (GumExecCtx * ctx)
{
  GumCodeSlab * slab;
  GumStalker * stalker = ctx->stalker;
  const gsize slab_size = stalker->code_slab_size_dynamic;
  GumAddressSpec spec;

  gum_exec_ctx_compute_code_address_spec (ctx, slab_size, &spec);

  slab = gum_memory_allocate_near (&spec, slab_size, stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  gum_code_slab_init (slab, slab_size, stalker->page_size);

  return slab;
}

static void
gum_code_slab_free (GumCodeSlab * code_slab)
{
  gum_slab_free (&code_slab->slab);
}

static void
gum_code_slab_init (GumCodeSlab * code_slab,
                    gsize slab_size,
                    gsize page_size)
{
  /*
   * We don't want to thaw and freeze the header just to update the offset,
   * so we trade a little memory for speed.
   */
  const gsize header_size = GUM_ALIGN_SIZE (sizeof (GumCodeSlab), page_size);

  gum_slab_init (&code_slab->slab, slab_size, header_size);

  code_slab->invalidator = NULL;
}

static GumDataSlab *
gum_data_slab_new (GumExecCtx * ctx)
{
  GumDataSlab * slab;
  GumStalker * stalker = ctx->stalker;
  const gsize slab_size = stalker->data_slab_size_dynamic;
  GumAddressSpec spec;

  gum_exec_ctx_compute_data_address_spec (ctx, slab_size, &spec);

  slab = gum_memory_allocate_near (&spec, slab_size, stalker->page_size,
      GUM_PAGE_RW);

  gum_data_slab_init (slab, slab_size);

  return slab;
}

static void
gum_data_slab_free (GumDataSlab * data_slab)
{
  gum_slab_free (&data_slab->slab);
}

static void
gum_data_slab_init (GumDataSlab * data_slab,
                    gsize slab_size)
{
  GumSlab * slab = &data_slab->slab;
  const gsize header_size = sizeof (GumDataSlab);

  gum_slab_init (slab, slab_size, header_size);
}

static void
gum_scratch_slab_init (GumCodeSlab * scratch_slab,
                       gsize slab_size)
{
  const gsize header_size = sizeof (GumCodeSlab);

  gum_slab_init (&scratch_slab->slab, slab_size, header_size);

  scratch_slab->invalidator = NULL;
}

static void
gum_slab_free (GumSlab * slab)
{
  const gsize header_size = slab->data - (guint8 *) slab;

  gum_memory_free (slab, header_size + slab->size);
}

static void
gum_slab_init (GumSlab * slab,
               gsize slab_size,
               gsize header_size)
{
  slab->data = (guint8 *) slab + header_size;
  slab->offset = 0;
  slab->size = slab_size - header_size;
  slab->next = NULL;
}

static gsize
gum_slab_available (GumSlab * self)
{
  return self->size - self->offset;
}

static gpointer
gum_slab_start (GumSlab * self)
{
  return self->data;
}

static gpointer
gum_slab_end (GumSlab * self)
{
  return self->data + self->size;
}

static gpointer
gum_slab_cursor (GumSlab * self)
{
  return self->data + self->offset;
}

static gpointer
gum_slab_reserve (GumSlab * self,
                  gsize size)
{
  gpointer cursor;

  cursor = gum_slab_try_reserve (self, size);
  g_assert (cursor != NULL);

  return cursor;
}

static gpointer
gum_slab_try_reserve (GumSlab * self,
                      gsize size)
{
  gpointer cursor;

  if (gum_slab_available (self) < size)
    return NULL;

  cursor = gum_slab_cursor (self);
  self->offset += size;

  return cursor;
}

static gpointer
gum_find_thread_exit_implementation (void)
{
#ifdef HAVE_DARWIN
  guint32 * cursor;

  cursor = GSIZE_TO_POINTER (gum_strip_code_address (
      gum_module_find_export_by_name ("/usr/lib/system/libsystem_pthread.dylib",
          "pthread_exit")));

  do
  {
    guint32 insn = *cursor;

    if (gum_is_bl_imm (insn))
    {
      union
      {
        gint32 i;
        guint32 u;
      } distance;

      distance.u = insn & GUM_INT26_MASK;
      if ((distance.u & (1 << (26 - 1))) != 0)
        distance.u |= 0xfc000000;

      return cursor + distance.i;
    }

    cursor++;
  }
  while (TRUE);
#else
  return NULL;
#endif
}


static gboolean
gum_is_mov_reg_reg (guint32 insn)
{
  return (insn & 0xffe0ffe0) == 0xaa0003e0;
}

static gboolean
gum_is_mov_x16_reg (guint32 insn)
{
  return (insn & 0xffe0ffff) == 0xaa0003f0;
}

static gboolean
gum_is_ldr_x16_pcrel (guint32 insn)
{
  return (insn & 0xff00001f) == 0x58000010;
}

static gboolean
gum_is_b_imm (guint32 insn)
{
  return (insn & ~GUM_INT26_MASK) == 0x14000000;
}

static gboolean
gum_is_bl_imm (guint32 insn)
{
  return (insn & ~GUM_INT26_MASK) == 0x94000000;
}
