/*
 * Copyright (C) 2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumstalker.h"

#include "gummetalhash.h"
#include "gumarm64reader.h"
#include "gumarm64writer.h"
#include "gummemory.h"
#include "gumarm64relocator.h"
#include "gumspinlock.h"
#include "gumtls.h"

#include <stdlib.h>
#include <string.h>

#define GUM_CODE_SLAB_SIZE_IN_PAGES         1024
#define GUM_EXEC_BLOCK_MIN_SIZE             1024

#define ARM64_STALKER_REG_CTX ARM64_REG_X12

#define STALKER_LOAD_REG_FROM_CTX(ARM64_REG, FIELD)\
    gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG, ARM64_STALKER_REG_CTX, \
    G_STRUCT_OFFSET (GumExecCtx, FIELD));

#define STALKER_LOAD_REG_FROM_CTX_WITH_AO(ARM64_REG, FIELD, ADDITIONAL_OFFSET)\
    gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG, ARM64_STALKER_REG_CTX, \
    G_STRUCT_OFFSET (GumExecCtx, FIELD)+ADDITIONAL_OFFSET);

#define STALKER_STORE_REG_INTO_CTX(ARM64_REG, FIELD)\
    gum_arm64_writer_put_str_reg_reg_offset(cw, ARM64_REG, ARM64_STALKER_REG_CTX, \
    G_STRUCT_OFFSET (GumExecCtx, FIELD));

#define STALKER_STORE_REG_INTO_CTX_WITH_AO(ARM64_REG, FIELD, ADDITIONAL_OFFSET)\
    gum_arm64_writer_put_str_reg_reg_offset(cw, ARM64_REG, ARM64_STALKER_REG_CTX, \
    G_STRUCT_OFFSET (GumExecCtx, FIELD) + ADDITIONAL_OFFSET);


#define ENABLE_DEBUG 0
#if ENABLE_DEBUG == 0
#undef ENABLE_DEBUG
#endif

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;

typedef struct _GumCallProbe GumCallProbe;
typedef struct _GumSlab GumSlab;

typedef struct _GumExecFrame GumExecFrame;
typedef struct _GumExecCtx GumExecCtx;
typedef struct _GumExecBlock GumExecBlock;

typedef guint GumPrologType;
typedef guint GumCodeContext;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;

typedef guint GumVirtualizationRequirements;

struct _GumStalkerPrivate
{
    guint page_size;

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
};

struct _GumInfectContext
{
    GumStalker * stalker;
    GumEventSink * sink;
};

struct _GumDisinfectContext
{
    GumStalker * stalker;
    GumExecCtx * exec_ctx;
    gboolean success;
};

struct _GumCallProbe
{
    GumProbeId id;
    GumCallProbeCallback callback;
    gpointer user_data;
    GDestroyNotify user_notify;
};

struct _GumSlab
{
    guint8 * data;
    guint offset;
    guint size;
    GumSlab * next;
};

struct _GumExecFrame
{
    gpointer real_address;
    gpointer code_address;
};

enum _GumExecCtxState
{
    GUM_EXEC_CTX_ACTIVE,
    GUM_EXEC_CTX_UNFOLLOW_PENDING,
    GUM_EXEC_CTX_DESTROY_PENDING
};

struct _GumExecCtx
{
    volatile guint state;
    volatile gboolean invalidate_pending;

    GumStalker * stalker;
    GumThreadId thread_id;

    GumArm64Writer code_writer;
    GumArm64Relocator relocator;

    GumEventSink * sink;
    GumEventType sink_mask;
    gpointer sink_process_impl; /* cached */
    GumEvent tmp_event;

    gboolean unfollow_called_while_still_following;
    GumExecBlock * current_block;
    GumExecFrame * current_frame;
    GumExecFrame * first_frame;
    GumExecFrame * frames;

    gpointer resume_at;
    gpointer return_at;
    gpointer app_stack;

    gpointer thunks;
    gpointer infect_thunk;

    GumSlab * code_slab;
    GumSlab first_code_slab;
    GumMetalHashTable * mappings;
};

struct _GumExecBlock
{
    GumExecCtx * ctx;
    GumSlab * slab;

    guint8 * real_begin;
    guint8 * real_end;
    guint8 * real_snapshot;
    guint8 * code_begin;
    guint8 * code_end;

    guint8 state;
    gint recycle_count;
    gboolean has_call_to_excluded_range;
};

enum _GumExecState
{
    GUM_EXEC_NORMAL,
    GUM_EXEC_SINGLE_STEPPING_ON_CALL,
    GUM_EXEC_SINGLE_STEPPING_THROUGH_CALL
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
};

struct _GumInstruction
{
    cs_insn * ci;
    guint8 * begin;
    guint8 * end;
};

struct _GumBranchTarget
{
    gpointer origin_ip;

    gpointer absolute_address;
    gssize relative_offset;

    gboolean is_indirect;
    //uint8_t pfx_seg;
    arm64_reg base;
    arm64_reg index;
    int32_t disp;
};

enum _GumVirtualizationRequirements
{
    GUM_REQUIRE_NOTHING         = 0,

    GUM_REQUIRE_RELOCATION      = 1 << 0,
    GUM_REQUIRE_SINGLE_STEP     = 1 << 1
};

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->priv->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->priv->mutex)

#define GUM_STALKER_GET_PRIVATE(o) ((o)->priv)

//TODO DELETE IFDEF HERE

static void gum_stalker_finalize (GObject * object);

G_GNUC_INTERNAL gpointer _gum_stalker_do_follow_me (GumStalker * self,
                                                GumEventSink * sink, volatile gpointer ret_addr);
void _gum_stalker_do_unfollow_me (GumStalker * self);
static void gum_stalker_infect (GumThreadId thread_id,
                                GumCpuContext * cpu_context, gpointer user_data);
static void gum_stalker_disinfect (GumThreadId thread_id,
                                   GumCpuContext * cpu_context, gpointer user_data);

static void gum_stalker_free_probe_array (gpointer data);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
                                                 GumThreadId thread_id, GumEventSink * sink);
static GumExecCtx * gum_stalker_get_exec_ctx (GumStalker * self);
static void gum_stalker_invalidate_caches (GumStalker * self);

static void gum_exec_ctx_free (GumExecCtx * ctx);
static void gum_exec_ctx_unfollow (GumExecCtx * ctx, gpointer resume_at);
static gboolean gum_exec_ctx_has_executed (GumExecCtx * ctx);
static gpointer gum_exec_ctx_replace_current_block_with (
        GumExecCtx * ctx, gpointer start_address);
static void gum_exec_ctx_create_thunks (GumExecCtx * ctx);
static void gum_exec_ctx_destroy_thunks (GumExecCtx * ctx);

static GumExecBlock * gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
                                                     gpointer real_address, gpointer * code_address);
static void gum_exec_ctx_write_prolog (GumExecCtx * ctx, GumPrologType type,
                                       gpointer ip, GumArm64Writer * cw);
static void gum_exec_ctx_write_epilog (GumExecCtx * ctx, GumPrologType type,
                                       GumArm64Writer * cw);
static void gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
                                                           const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                                  arm64_reg target_register, arm64_reg source_register,
                                                  gpointer ip, GumGeneratorContext * gc);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static GumExecBlock * gum_exec_block_obtain (GumExecCtx * ctx,
                                             gpointer real_address, gpointer * code_address);
static gboolean gum_exec_block_is_full (GumExecBlock * block);
static void gum_exec_block_commit (GumExecBlock * block);

static void gum_exec_block_backpatch_call (GumExecBlock * block,
                                           gpointer code_start, GumPrologType opened_prolog, gpointer target_address,
                                           gpointer ret_real_address, gpointer ret_code_address);
static void gum_exec_block_backpatch_jmp (GumExecBlock * block,
                                          gpointer code_start, GumPrologType opened_prolog, gpointer target_address);
static void gum_exec_block_backpatch_ret (GumExecBlock * block,
                                          gpointer code_start, gpointer target_address);

static GumVirtualizationRequirements gum_exec_block_virtualize_branch_insn (
        GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_ret_insn (
        GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_sysenter_insn (
        GumExecBlock * block, GumGeneratorContext * gc);

static void gum_exec_block_write_call_invoke_code (GumExecBlock * block,
                                                   const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                                    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                                    GumGeneratorContext * gc);
static void gum_exec_block_write_single_step_transfer_code (
        GumExecBlock * block, GumGeneratorContext * gc);

static void gum_exec_block_write_call_event_code (GumExecBlock * block,
                                                  const GumBranchTarget * target, GumGeneratorContext * gc,
                                                  GumCodeContext cc);
static void gum_exec_block_write_ret_event_code (GumExecBlock * block,
                                                 GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_exec_event_code (GumExecBlock * block,
                                                  GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_event_init_code (GumExecBlock * block,
                                                  GumEventType type, GumGeneratorContext * gc);
static void gum_exec_block_write_event_submit_code (GumExecBlock * block,
                                                    GumGeneratorContext * gc, GumCodeContext cc);

static void gum_exec_block_write_call_probe_code (GumExecBlock * block,
                                                  const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_open_prolog (GumExecBlock * block,
                                        GumPrologType type, GumGeneratorContext * gc);
static void gum_exec_block_close_prolog (GumExecBlock * block,
                                         GumGeneratorContext * gc);

static void gum_write_segment_prefix (uint8_t segment, GumArm64Writer * cw);

static GumArm64MetaReg gum_cpu_meta_reg_from_real_reg (GumArm64MetaReg reg);
static GumArm64MetaReg gum_cpu_reg_from_capstone (arm64_reg reg);


G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT);

#ifdef ENABLE_DEBUG
static void debug_hello(gpointer);

static void debug_hello(gpointer pointer){
    g_print("######### hello #########\n");
    printf("# pointer: %p #\n", pointer);
    g_print("#########################\n");
}

static void put_debug_print(GumArm64Writer* cw, gpointer pointer){
    gum_arm64_writer_put_push_all_registers(cw);
    gum_arm64_writer_put_call_address_with_arguments(cw,
                                                     GUM_FUNCPTR_TO_POINTER (debug_hello), 1,
                                                     GUM_ARG_ADDRESS, GUM_ADDRESS(pointer));
    gum_arm64_writer_put_pop_all_registers(cw);

}

static void put_debug_print_reg(GumArm64Writer* cw, arm64_reg reg){
    gum_arm64_writer_put_push_all_registers(cw);
    gum_arm64_writer_put_call_address_with_arguments(cw,
                                                     GUM_FUNCPTR_TO_POINTER (debug_hello), 1,
                                                     GUM_ARG_REGISTER, reg);
    gum_arm64_writer_put_pop_all_registers(cw);
}

#endif


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

    self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_STALKER, GumStalkerPrivate);
    priv = GUM_STALKER_GET_PRIVATE (self);

    priv->exclusions = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
    priv->trust_threshold = 1;

    gum_spinlock_init (&priv->probe_lock);
    priv->probe_target_by_id =
            g_hash_table_new_full (NULL, NULL, NULL, NULL);
    priv->probe_array_by_address =
            g_hash_table_new_full (NULL, NULL, NULL, gum_stalker_free_probe_array);

    priv->page_size = gum_query_page_size ();
    g_mutex_init (&priv->mutex);
    priv->contexts = NULL;
    priv->exec_ctx = gum_tls_key_new ();
}

static void
gum_stalker_finalize (GObject * object)
{
    GumStalker * self = GUM_STALKER (object);
    GumStalkerPrivate * priv = self->priv;

    g_hash_table_unref (priv->probe_array_by_address);
    g_hash_table_unref (priv->probe_target_by_id);

    gum_spinlock_free (&priv->probe_lock);

    g_array_free (priv->exclusions, TRUE);

    g_assert (priv->contexts == NULL);
    gum_tls_key_free (priv->exec_ctx);
    g_mutex_clear (&priv->mutex);

    G_OBJECT_CLASS (gum_stalker_parent_class)->finalize (object);
}

GumStalker *
gum_stalker_new (void)
{
  return GUM_STALKER (g_object_new (GUM_TYPE_STALKER, NULL));
}

void
gum_stalker_exclude (GumStalker * self,
        const GumMemoryRange * range)
{
    g_array_append_val (self->priv->exclusions, *range);
}

gint
gum_stalker_get_trust_threshold (GumStalker * self)
{
    return self->priv->trust_threshold;
}

void
gum_stalker_set_trust_threshold (GumStalker * self,
                                 gint trust_threshold)
{
    self->priv->trust_threshold = trust_threshold;
}

void
gum_stalker_stop (GumStalker * self)
{
    GumStalkerPrivate * priv = self->priv;
    gboolean rescan_needed;
    GSList * cur;

    gum_spinlock_acquire (&priv->probe_lock);
    g_hash_table_remove_all (priv->probe_target_by_id);
    g_hash_table_remove_all (priv->probe_array_by_address);
    priv->any_probes_attached = FALSE;
    gum_spinlock_release (&priv->probe_lock);

    GUM_STALKER_LOCK (self);

    do
    {
        rescan_needed = FALSE;

        for (cur = priv->contexts; cur != NULL; cur = cur->next)
        {
            GumExecCtx * ctx = (GumExecCtx *) cur->data;
            if (ctx->state == GUM_EXEC_CTX_ACTIVE)
            {
                GumThreadId thread_id = ctx->thread_id;

                GUM_STALKER_UNLOCK (self);
                gum_stalker_unfollow (self, thread_id);
                GUM_STALKER_LOCK (self);

                rescan_needed = TRUE;
                break;
            }
        }
    }
    while (rescan_needed);

    GUM_STALKER_UNLOCK (self);

    gum_stalker_garbage_collect (self);

}

gboolean
gum_stalker_garbage_collect (GumStalker * self)
{
    GSList * keep = NULL, * cur;
    gboolean pending_garbage;

    GUM_STALKER_LOCK (self);

    for (cur = self->priv->contexts; cur != NULL; cur = cur->next)
    {
        GumExecCtx * ctx = (GumExecCtx *) cur->data;
        if (ctx->state == GUM_EXEC_CTX_DESTROY_PENDING)
            gum_exec_ctx_free (ctx);
        else
            keep = g_slist_prepend (keep, ctx);
    }

    g_slist_free (self->priv->contexts);
    self->priv->contexts = keep;

    pending_garbage = keep != NULL;

    GUM_STALKER_UNLOCK (self);

    return pending_garbage;
}

gpointer
_gum_stalker_do_follow_me (GumStalker * self,
                           GumEventSink * sink,
                            volatile gpointer ret_addr)
{
#ifdef ENABLE_DEBUG
    g_print("_gum_stalker_do_follow_me - enter\n");
    printf("\tret_addr_ptr: %p\n", ret_addr);
    g_print("\tnext actual instruction to execute after\n");
#endif

    GumExecCtx * ctx;
    gpointer code_address;

    ctx = gum_stalker_create_exec_ctx (self, gum_process_get_current_thread_id (), sink);
    gum_tls_key_set_value (self->priv->exec_ctx, ctx);

    ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, ret_addr, &code_address);

    gum_event_sink_start (sink);

#ifdef ENABLE_DEBUG
    g_print("_gum_stalker_do_follow_me - exit\n");
    printf("\tcode_address: %p\n", code_address);
    g_print("\tnext stalker instruction to execute after!\n");
    printf("self %p\n", self);
#endif

    g_assert (ctx != NULL);
    g_assert (gum_stalker_get_exec_ctx (self) != NULL);

    return code_address;

}

void _gum_stalker_do_unfollow_me (GumStalker * self){
#ifdef ENABLE_DEBUG
    g_print("gum_stalker_unfollow_me - enter\n");
#endif

    GumExecCtx * ctx;

    ctx = gum_stalker_get_exec_ctx (self);
    g_assert (ctx != NULL);


    gum_event_sink_stop (ctx->sink);

    if (ctx->current_block != NULL && ctx->current_block->has_call_to_excluded_range)
    {
#ifdef ENABLE_DEBUG
        g_print("\t- ctx->current_block != NULL && ctx->current_block->has_call_to_excluded_range\n");
#endif
        ctx->state = GUM_EXEC_CTX_UNFOLLOW_PENDING;
    }else
    {
#ifdef ENABLE_DEBUG
        g_print("\t- otherwise\n");
#endif

        g_assert (ctx->unfollow_called_while_still_following);

        gum_tls_key_set_value (self->priv->exec_ctx, NULL);

        GUM_STALKER_LOCK (self);
        self->priv->contexts = g_slist_remove (self->priv->contexts, ctx);
        GUM_STALKER_UNLOCK (self);

        gum_exec_ctx_free (ctx);
    }

#ifdef ENABLE_DEBUG
    g_print("gum_stalker_unfollow_me - exit\n");
#endif

}

/*void
gum_stalker_unfollow_me (GumStalker * self)
{

}*/

gboolean
gum_stalker_is_following_me (GumStalker * self)
{
    return gum_stalker_get_exec_ctx (self) != NULL;
}

void
gum_stalker_follow (GumStalker * self,
                    GumThreadId thread_id,
                    GumEventSink * sink)
{
    if (thread_id == gum_process_get_current_thread_id ()){
        gum_stalker_follow_me (self, sink);
    }else{
        GumInfectContext ctx;
        ctx.stalker = self;
        ctx.sink = sink;
        gum_process_modify_thread (thread_id, gum_stalker_infect, &ctx);
    }
}

void
gum_stalker_unfollow (GumStalker * self,
                      GumThreadId thread_id)
{
    if (thread_id == gum_process_get_current_thread_id ()){
        gum_stalker_unfollow_me (self);
    }
    else
    {
        GSList * cur;

        GUM_STALKER_LOCK (self);

        for (cur = self->priv->contexts; cur != NULL; cur = cur->next)
        {
            GumExecCtx * ctx = (GumExecCtx *) cur->data;
            if (ctx->thread_id == thread_id && ctx->state == GUM_EXEC_CTX_ACTIVE)
            {
                gum_event_sink_stop (ctx->sink);

                if (gum_exec_ctx_has_executed (ctx))
                {
                    ctx->state = GUM_EXEC_CTX_UNFOLLOW_PENDING;
                }
                else
                {
                    GumDisinfectContext dc;
                    dc.stalker = self;
                    dc.exec_ctx = ctx;
                    dc.success = FALSE;
                    gum_process_modify_thread (thread_id, gum_stalker_disinfect, &dc);
                    if (!dc.success)
                        ctx->state = GUM_EXEC_CTX_UNFOLLOW_PENDING;
                }

                break;
            }
        }

        GUM_STALKER_UNLOCK (self);
    }

}

static void
gum_stalker_infect (GumThreadId thread_id,
                    GumCpuContext * cpu_context,
                    gpointer user_data)
{

#ifdef ENABLE_DEBUB
    g_print("gum_stalker_infect - enter\n");
#endif

    GumInfectContext * infect_context = (GumInfectContext *) user_data;
    GumStalker * self = infect_context->stalker;
    GumExecCtx * ctx;
    gpointer code_address;
    GumArm64Writer cw;

    ctx = gum_stalker_create_exec_ctx (self, thread_id, infect_context->sink);

    ctx->current_block = gum_exec_ctx_obtain_block_for (ctx,
                                                        GSIZE_TO_POINTER ((cpu_context)->pc), &code_address);
    (cpu_context)->pc = GPOINTER_TO_SIZE (ctx->infect_thunk);

    gum_arm64_writer_init (&cw, ctx->infect_thunk);
    gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL,
                               ctx->current_block->real_begin, &cw);
    //gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, align_correction);
    gum_arm64_writer_put_call_address_with_arguments(&cw,
                                                     GUM_FUNCPTR_TO_POINTER (gum_tls_key_set_value), 2,
                                                     GUM_ARG_POINTER, self->priv->exec_ctx,
                                                     GUM_ARG_POINTER, ctx);
    /*gum_x86_writer_put_call_with_arguments (&cw,
                                            GUM_FUNCPTR_TO_POINTER (gum_tls_key_set_value), 2,
                                            GUM_ARG_POINTER, self->priv->exec_ctx,
                                            GUM_ARG_POINTER, ctx);*/
    //gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, align_correction);
    gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, &cw);
    gum_arm64_writer_put_branch_address(&cw, code_address);
    //gum_arm64_writer_put_b_imm(&cw, code_address);
    // gum_x86_writer_put_jmp (&cw, code_address);
    gum_arm64_writer_free(&cw);//gum_x86_writer_free (&cw);

    gum_event_sink_start (infect_context->sink);
}

static void
gum_stalker_disinfect (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{

#ifdef ENABLE_DEBUB
    g_print("gum_stalker_disinfect - enter\n");
#endif

    GumDisinfectContext * disinfect_context = (GumDisinfectContext *) user_data;
    GumStalker * self = disinfect_context->stalker;
    GumExecCtx * ctx = disinfect_context->exec_ctx;
    gboolean infection_not_active_yet;

    (void) thread_id;

    infection_not_active_yet =
            (cpu_context)->pc == GPOINTER_TO_SIZE (ctx->infect_thunk);
    if (infection_not_active_yet)
    {
        (cpu_context)->pc =
                GPOINTER_TO_SIZE (ctx->current_block->real_begin);

        self->priv->contexts = g_slist_remove (self->priv->contexts, ctx);
        gum_exec_ctx_free (ctx);

        disinfect_context->success = TRUE;
    }
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

    probe.id = g_atomic_int_add (&priv->last_probe_id, 1) + 1;
    probe.callback = callback;
    probe.user_data = data;
    probe.user_notify = notify;

    gum_spinlock_acquire (&priv->probe_lock);

    g_hash_table_insert (priv->probe_target_by_id,
                        GSIZE_TO_POINTER (probe.id),
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

    gum_stalker_invalidate_caches (self);

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

    gum_stalker_invalidate_caches (self);

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
                                     GumThreadId thread_id,
GumEventSink * sink)
{
    GumStalkerPrivate * priv = self->priv;
    guint base_size;
    GumExecCtx * ctx;

    base_size = sizeof (GumExecCtx) / priv->page_size;
    if (sizeof (GumExecCtx) % priv->page_size != 0)
        base_size++;

    ctx = (GumExecCtx *)
            gum_alloc_n_pages (base_size + GUM_CODE_SLAB_SIZE_IN_PAGES + 1,
                               GUM_PAGE_RWX);
    ctx->state = GUM_EXEC_CTX_ACTIVE;
    ctx->invalidate_pending = FALSE;

    ctx->code_slab = &ctx->first_code_slab;
    ctx->first_code_slab.data = ((guint8 *) ctx) + (base_size * priv->page_size);
    ctx->first_code_slab.offset = 0;
    ctx->first_code_slab.size = GUM_CODE_SLAB_SIZE_IN_PAGES * priv->page_size;
    ctx->first_code_slab.next = NULL;

    ctx->frames = (GumExecFrame *)
            (ctx->code_slab->data + ctx->code_slab->size);
    ctx->first_frame = (GumExecFrame *) (ctx->code_slab->data +
                                         ctx->code_slab->size + priv->page_size - sizeof (GumExecFrame));
    ctx->current_frame = ctx->first_frame;

    ctx->mappings = gum_metal_hash_table_new (NULL, NULL);

    ctx->resume_at = NULL;
    ctx->return_at = NULL;
    ctx->app_stack = NULL;

    ctx->stalker = g_object_ref (self);
    ctx->thread_id = thread_id;

    gum_arm64_writer_init (&ctx->code_writer, NULL);
    gum_arm64_relocator_init (&ctx->relocator, NULL, &ctx->code_writer);

    ctx->sink = (GumEventSink *) g_object_ref (sink);
    ctx->sink_mask = gum_event_sink_query_mask (sink);
    ctx->sink_process_impl = GUM_FUNCPTR_TO_POINTER (
            GUM_EVENT_SINK_GET_INTERFACE (sink)->process);

#ifdef ENABLE_DEBUG
    printf("sink mask= %ld\n", ctx->sink_mask);
#endif

    gum_exec_ctx_create_thunks (ctx);

    GUM_STALKER_LOCK (self);
    self->priv->contexts = g_slist_prepend (self->priv->contexts, ctx);
    GUM_STALKER_UNLOCK (self);

    return ctx;
}

static GumExecCtx *
gum_stalker_get_exec_ctx (GumStalker * self)
{
    return (GumExecCtx *) gum_tls_key_get_value (self->priv->exec_ctx);
}

static void
gum_stalker_invalidate_caches (GumStalker * self)
{
    GSList * cur;

    GUM_STALKER_LOCK (self);

    for (cur = self->priv->contexts; cur != NULL; cur = cur->next)
    {
        GumExecCtx * ctx = (GumExecCtx *) cur->data;

        ctx->invalidate_pending = TRUE;
    }

    GUM_STALKER_UNLOCK (self);
}

static void
gum_exec_ctx_free (GumExecCtx * ctx)
{
    GumSlab * slab;

    gum_metal_hash_table_unref (ctx->mappings);

    slab = ctx->code_slab;
    while (slab != &ctx->first_code_slab)
    {
        GumSlab * next = slab->next;
        gum_free_pages (slab);
        slab = next;
    }

    gum_exec_ctx_destroy_thunks (ctx);

    g_object_unref (ctx->sink);

    gum_arm64_relocator_free (&ctx->relocator);
    gum_arm64_writer_free (&ctx->code_writer);

    g_object_unref (ctx->stalker);

    gum_free_pages (ctx);
}


static void
gum_exec_ctx_unfollow (GumExecCtx * ctx,
                       gpointer resume_at)
{
    ctx->resume_at = resume_at;

    gum_tls_key_set_value (ctx->stalker->priv->exec_ctx, NULL);
    ctx->current_block = NULL;
    ctx->state = GUM_EXEC_CTX_DESTROY_PENDING;
}

static gboolean
gum_exec_ctx_has_executed (GumExecCtx * ctx)
{
    return ctx->resume_at != NULL;
}


static gpointer gum_exec_ctx_replace_current_block_with (GumExecCtx * ctx, gpointer start_address)
{

#ifdef ENABLE_DEBUG
    g_print("gum_exec_ctx_replace_current_block_with - enter\n");
    printf ("\tstart_address (real_address) %p:\n", start_address);
    printf ("\tresume_at (code_address) %p:\n", ctx->resume_at);
    printf ("\tgum_stalker_unfollow_me: %p\n", gum_stalker_unfollow_me);
#endif

    if (ctx->invalidate_pending)
    {
#ifdef ENABLE_DEBUG
        g_print("gum_exec_ctx_replace_current_block_with - invalidate_pending\n");
#endif
        gum_metal_hash_table_remove_all (ctx->mappings);

        ctx->invalidate_pending = FALSE;
    }

    if (start_address == gum_stalker_unfollow_me)
    {
#ifdef ENABLE_DEBUG
        g_print("gum_exec_ctx_replace_current_block_with - gum_stalker_unfollow_me\n");
#endif

        ctx->unfollow_called_while_still_following = TRUE;
        ctx->current_block = NULL;

        ctx->resume_at = start_address;

    }
    else if (ctx->state == GUM_EXEC_CTX_UNFOLLOW_PENDING)
    {
#ifdef ENABLE_DEBUG
        g_print("gum_exec_ctx_replace_current_block_with - GUM_EXEC_CTX_UNFOLLOW_PENDING\n");
#endif
        gum_exec_ctx_unfollow (ctx, start_address);
    }
    else
    {
#ifdef ENABLE_DEBUG
        g_print("gum_exec_ctx_replace_current_block_with - gum_exec_ctx_obtain_block_for\n");
        printf ("\tstart_address (real_address) %p:\n", start_address);
        printf ("\tresume_at (code_address) %p:\n", ctx->resume_at);
#endif

        ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, start_address,
                                                            &ctx->resume_at);
    }

#ifdef ENABLE_DEBUG
    g_print("gum_exec_ctx_replace_current_block_with - exit\n");
    printf("\treturn ctx->resume_at %p\n", ctx->resume_at);
    g_print("gum_exec_ctx_replace_current_block_with - exit\n");
    printf("\treturn ctx->resume_at %p\n", ctx->resume_at);
    g_print("gum_exec_ctx_replace_current_block_with - exit\n");
#endif

    return ctx->resume_at;
}

static void
gum_exec_ctx_create_thunks (GumExecCtx * ctx)
{
    GumArm64Writer cw;

    g_assert (ctx->thunks == NULL);

    ctx->thunks = gum_alloc_n_pages (1, GUM_PAGE_RWX);
    gum_arm64_writer_init (&cw, ctx->thunks);

    ctx->infect_thunk = gum_arm64_writer_cur (&cw);

    gum_arm64_writer_free (&cw);
}

static void
gum_exec_ctx_destroy_thunks (GumExecCtx * ctx)
{
    gum_free_pages (ctx->thunks);
}

#if ENABLE_DEBUG

static void
gum_disasm (guint8 * code, guint size, const gchar * prefix)
{
  csh capstone;
  cs_err err;
  cs_insn * insn;
  size_t count, i;

  err = cs_open (CS_ARCH_ARM64, CS_MODE_ARM, &capstone);
  g_assert_cmpint (err, == , CS_ERR_OK);

  count = cs_disasm (capstone, code, size, GPOINTER_TO_SIZE (code), 0, &insn);
  g_assert (insn != NULL);

  for (i = 0; i != count; i++)
  {
    printf ("%s0x%" G_GINT64_MODIFIER "x\t(0x",
        prefix, insn[i].address);

      for (int j = 0; j<insn[i].size; j++){
          printf("%02X",(unsigned)insn[i].bytes[j]);
      }

      printf (")\t%s %s\x1b[0m\n", insn[i].mnemonic, insn[i].op_str);

  }

  cs_free (insn, count);

  cs_close (&capstone);
}

#endif


static GumExecBlock *
gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
                               gpointer real_address,
                               gpointer * code_address_ptr)
{

#if ENABLE_DEBUG
    g_print("gum_exec_ctx_obtain_block_for - enter\n");
    printf ("\treal_address (former ret_address): %p\n", real_address);
    printf ("\tcode_address_ptr: %p\n", code_address_ptr);
    printf ("\tcode_address: %p\n", *code_address_ptr);
#endif

    GumExecBlock * block;
    GumArm64Writer * cw = &ctx->code_writer;
    GumArm64Relocator * rl = &ctx->relocator;
    GumGeneratorContext gc;

    if (ctx->stalker->priv->trust_threshold >= 0)
    {
#if ENABLE_DEBUG
        g_print("ctx->stalker->priv->trust_threshold >= 0\n");
#endif
        block = gum_exec_block_obtain (ctx, real_address, code_address_ptr);
        if (block != NULL)
        {
            if (block->recycle_count >= ctx->stalker->priv->trust_threshold ||
                memcmp (real_address, block->real_snapshot,
                        block->real_end - block->real_begin) == 0)
            {
                block->recycle_count++;
                g_print("gum_exec_ctx_obtain_block_for - fast exit\n");
                return block;
            }
            else
            {
                gum_metal_hash_table_remove (ctx->mappings, real_address);
            }
        }
    }

    block = gum_exec_block_new (ctx);
    *code_address_ptr = block->code_begin;
#if ENABLE_DEBUG
    g_print("new block!\n");
    printf ("\tcode_address_ptr: %p\n", code_address_ptr);
    printf ("\tcode_address: %p\n", *code_address_ptr);
#endif

    if (ctx->stalker->priv->trust_threshold >= 0)
        gum_metal_hash_table_insert (ctx->mappings, real_address, block);
    gum_arm64_writer_reset (cw, block->code_begin);
    gum_arm64_relocator_reset (rl, real_address, cw);

    gc.instruction = NULL;
    gc.relocator = rl;
    gc.code_writer = cw;
    gc.continuation_real_address = NULL;
    gc.opened_prolog = GUM_PROLOG_NONE;

#if ENABLE_DEBUG
    printf ("\n\n*********************\n\nCreating block for %p (real_address):\n", real_address);
    int i = 0;
#endif

    gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X16, ARM64_REG_X17);

    while (TRUE)
    {
        guint n_read;
        GumInstruction insn;
        GumVirtualizationRequirements requirements = GUM_REQUIRE_NOTHING;

        n_read = gum_arm64_relocator_read_one (rl, NULL);
        g_assert_cmpuint (n_read, !=, 0);

        insn.ci = gum_arm64_relocator_peek_next_write_insn (rl);
        insn.begin = gum_arm64_relocator_peek_next_write_source (rl);
        insn.end = insn.begin + insn.ci->size;

        g_assert (insn.ci != NULL && insn.begin != NULL);

#if ENABLE_DEBUG
        gum_disasm (insn.begin, insn.ci->size, "\x1b[31mINS > ");
#endif

        gc.instruction = &insn;

        if ((ctx->sink_mask & GUM_EXEC) != 0)
            gum_exec_block_write_exec_event_code (block, &gc, GUM_CODE_INTERRUPTIBLE);

        switch (insn.ci->id)
        {
            case ARM64_INS_BL: //X86_INS_CALL
            case ARM64_INS_B: //X86_INS_JMP
            case ARM64_INS_BLR:
            case ARM64_INS_BR:
            case ARM64_INS_CBZ:
            case ARM64_INS_CBNZ:
            case ARM64_INS_TBZ:
            case ARM64_INS_TBNZ:
#ifdef ENABLE_DEBUG
                g_print("gum_exec_ctx_obtain_block_for - switch branch ins\n");
#endif
                requirements = gum_exec_block_virtualize_branch_insn (block, &gc);
                break;

            case ARM64_INS_RET: //X86_INS_RET:
#ifdef ENABLE_DEBUG
                g_print("gum_exec_ctx_obtain_block_for - switch ret ins\n");
#endif
                requirements = gum_exec_block_virtualize_ret_insn (block, &gc);
                break;

            case ARM64_INS_SVC://X86_INS_SYSENTER
            case ARM64_INS_SMC:
            case ARM64_INS_HVC:
#ifdef ENABLE_DEBUG
                g_print("gum_exec_ctx_obtain_block_for - switch sys ins - TO IMPLEMENT\n");
#endif
                requirements = gum_exec_block_virtualize_sysenter_insn (block, &gc);
                break;
            default:
                requirements = GUM_REQUIRE_RELOCATION;
        }

        gum_exec_block_close_prolog (block, &gc);

        if ((requirements & GUM_REQUIRE_RELOCATION) != 0)
        {
            gum_arm64_relocator_write_one(rl);//gum_x86_relocator_write_one_no_label (rl);
        }
        else if ((requirements & GUM_REQUIRE_SINGLE_STEP) != 0)
        {
            gum_arm64_relocator_skip_one(rl);//gum_x86_relocator_skip_one_no_label (rl);
            gum_exec_block_write_single_step_transfer_code (block, &gc);
        }

#if ENABLE_DEBUG
        {
            guint8 * begin = block->code_end;
            block->code_end = gum_arm64_writer_cur (cw);
            gum_disasm (begin, block->code_end - begin, "\x1b[34mNEW INS> ");
        }
#else
        block->code_end = gum_arm64_writer_cur (cw);
#endif

        if (gum_exec_block_is_full (block))
        {
            gc.continuation_real_address = insn.end;
#ifdef ENABLE_DEBUG
            g_print("gum_exec_ctx_obtain_block_for - block is full\n");
            printf("gc.continuation_real_address: %p", gc.continuation_real_address);
#endif
            break;
        }
        else if (insn.ci->id == ARM64_INS_BL)//X86_INS_CALL)
        {
            /* We always stop on a call unless it's to an excluded range */
            if ((requirements & GUM_REQUIRE_RELOCATION) != 0)
            {
#ifdef ENABLE_DEBUG
                g_print("gum_exec_ctx_obtain_block_for - block is not full\n");
                g_print("(requirements & GUM_REQUIRE_RELOCATION) != 0\n");
                g_print("rl->eob = FALSE");
#endif
                rl->eob = FALSE;
            }
            else
            {
                break;
            }
        }
        else if (gum_arm64_relocator_eob (rl))
        {
            break;
        }
    }

    if (gc.continuation_real_address != NULL)
    {
        GumBranchTarget continue_target = { 0, };

        continue_target.is_indirect = FALSE;
        continue_target.absolute_address = gc.continuation_real_address;
#ifdef ENABLE_DEBUG
        g_print("gum_exec_ctx_obtain_block_for - gc.continuation_real_address != NULL\n");
        printf("continue_target.absolute_address: %p", continue_target.absolute_address);
#endif
        gum_exec_block_write_jmp_transfer_code (block, &continue_target, &gc);
    }

    gum_arm64_writer_put_brk_imm(cw, 14);
    //gum_x86_writer_put_breakpoint (cw); /* should never get here */

    gum_arm64_writer_flush (cw);

    block->code_end = (guint8 *) gum_arm64_writer_cur (cw);

    block->real_begin = (guint8 *) rl->input_start;
    block->real_end = (guint8 *) rl->input_cur;

    gum_exec_block_commit (block);

#ifdef ENABLE_DEBUG
    g_print("gum_exec_ctx_obtain_block_for - exit\n");
    printf ("\tcode_address_ptr: %p\n", code_address_ptr);
    printf ("\tcode_address: %p\n", *code_address_ptr);
    printf("\tblock->code_begin: %p\n", block->code_begin);
    printf("\tblock->code_end: %p\n", block->code_end);
    printf("\tblock->real_begin: %p\n", block->real_begin);
    printf("\tblock->real_end: %p\n", block->real_end);
#endif
    return block;
}

static void
gum_exec_ctx_write_prolog (GumExecCtx * ctx,
                           GumPrologType type,
                           gpointer ip,
                           GumArm64Writer * cw)
{

#ifdef ENABLE_DEBUG
    printf ("+ gum_exec_ctx_write_prolog - type: %d\n",type);
#endif

    // 1) move to the red-zone
    gum_arm64_writer_put_sub_reg_reg_imm(cw, ARM64_REG_SP, ARM64_REG_SP, GUM_RED_ZONE_SIZE);

    // 2) push registers that are going to be clobbered
    int immediate_for_sp = GUM_RED_ZONE_SIZE;
    if (type == GUM_PROLOG_MINIMAL) {
        //save the register used by stalker's code

        gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X0, ARM64_REG_X1);
        gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X2, ARM64_REG_X3);
        gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X4, ARM64_REG_X5);
        gum_arm64_writer_put_push_reg_reg(cw, ARM64_STALKER_REG_CTX, ARM64_REG_X13);
        gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X14, ARM64_REG_X15);
        gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X16, ARM64_REG_X17);
        gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X29, ARM64_REG_X30);

        gum_arm64_writer_put_instruction(cw, 0xD53B420F);//MRS X15, NZCV
        gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X30, ARM64_REG_X15);

        // 8 push of 16
        immediate_for_sp += 16 * 8;
    }
    else{ //GUM_PROLOG_FULL

        gum_arm64_writer_put_push_all_registers(cw);// 16 push of 16
        gum_arm64_writer_put_push_all_Q_registers(cw); // 16 push of 32
        immediate_for_sp += (16*16)+(16*32);
    }

    // 3) save the stack pointer in context
    gum_arm64_writer_put_ldr_reg_address(cw, ARM64_STALKER_REG_CTX, GUM_ADDRESS (ctx));
    gum_arm64_writer_put_add_reg_reg_imm(cw, ARM64_REG_X14, ARM64_REG_SP, immediate_for_sp);
    STALKER_STORE_REG_INTO_CTX(ARM64_REG_X14, app_stack);


    if (type != GUM_PROLOG_MINIMAL){
        // 5) push the instruction pointer
        gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X15, GUM_ADDRESS (ip));
        gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X15, ARM64_REG_X15);

        // 6) save the stack pointer in the GumCpuContex.sp?
        STALKER_STORE_REG_INTO_CTX(ARM64_REG_X15, app_stack);
        gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X15, ARM64_REG_SP, G_STRUCT_OFFSET (GumCpuContext, sp));
        //gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_REG_XAX, GUM_ADDRESS (&ctx->app_stack));
        //gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_REG_XSP, G_STRUCT_OFFSET (GumCpuContext, sp), GUM_REG_XAX);
    }
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{

#ifdef ENABLE_DEBUG
    printf ("- gum_exec_ctx_write_epilog - type: %d\n",type);
#endif


    //TODO LOAD FLOATING POINT REGISTER

    if (type != GUM_PROLOG_MINIMAL) /* GUM_PROLOG_FULL */
    {
        gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X15, ARM64_REG_X15);
    }

    if (type == GUM_PROLOG_MINIMAL) {
        gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X30, ARM64_REG_X15);
        gum_arm64_writer_put_instruction(cw, 0xD51B420F);//msr NZCV, x15

        gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X29, ARM64_REG_X30);
        gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X16, ARM64_REG_X17);
        gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X14, ARM64_REG_X15);
        gum_arm64_writer_put_pop_reg_reg(cw, ARM64_STALKER_REG_CTX, ARM64_REG_X13);
        gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X4, ARM64_REG_X5);
        gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X2, ARM64_REG_X3);
        gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X0, ARM64_REG_X1);
    }
    else{ //GUM_PROLOG_FULL

        gum_arm64_writer_put_pop_all_Q_registers(cw);
        gum_arm64_writer_put_pop_all_registers(cw);

    }

    // restore the app_stack (with some tricks)
    gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_mov_reg_reg(cw, ARM64_REG_X14, ARM64_REG_SP);

    gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X15, GUM_ADDRESS (&ctx->app_stack));
    gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X15, ARM64_REG_X15, 0);
    gum_arm64_writer_put_mov_reg_reg(cw, ARM64_REG_SP, ARM64_REG_X15);

    gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X15, ARM64_REG_X14, 8);
    gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X14, ARM64_REG_X14, 0);

}



static void
gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
                                               const GumBranchTarget * target,
                                               GumGeneratorContext * gc)
{
    GumArm64Writer * cw = gc->code_writer;

#ifdef ENABLE_DEBUG
    g_print("gum_exec_ctx_write_push_branch_target_address - enter\n");
    printf("\ttarget is %sdirect\n", (target->is_indirect)?"in":"");
    printf("\ttarget->base is %svalid\n", (target->base == X86_REG_INVALID)?"in":"");
    printf("\ttarget->index  is %svalid\n", (target->index == X86_REG_INVALID)?"in":"");
#endif

    if (!target->is_indirect)
    {
        if (target->base == ARM64_REG_INVALID)
        {
            gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X15, GUM_ADDRESS (target->absolute_address));
            gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X15, ARM64_REG_X15);
        }
        else
        {
            gum_exec_ctx_load_real_register_into(ctx, ARM64_REG_X15, target->base, target->origin_ip, gc);
            gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X15, ARM64_REG_X15);

            //gum_arm64_writer_put_push_reg_reg(cw, target->base, target->base);
        }
    }
    else if (target->base == X86_REG_INVALID && target->index == X86_REG_INVALID)
    {
        g_assert("not yet implemented"=="");
    }
    else
    {
        g_assert("not yet implemented"=="");
    }

}

static void
gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                      arm64_reg target_register,
                                      arm64_reg source_register,
                                      gpointer ip,
                                      GumGeneratorContext * gc)
{

    GumArm64Writer * cw = gc->code_writer;

    if (source_register >= ARM64_REG_X0 && source_register <= ARM64_REG_X5){

        gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X15, GUM_ADDRESS (&ctx->app_stack));
        gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X15, ARM64_REG_X15, 0);
        gum_arm64_writer_put_sub_reg_reg_imm(cw, ARM64_REG_X15, ARM64_REG_X15,
                                             GUM_RED_ZONE_SIZE + (source_register-ARM64_REG_X0)*8);
        gum_arm64_writer_put_ldr_reg_reg_offset(cw, target_register, ARM64_REG_X15, 0);

    }else{
        g_assert(source_register=="not implemented");
    }


}

static GumExecBlock *
gum_exec_block_new (GumExecCtx * ctx)
{
    GumSlab * slab = ctx->code_slab;

    if (slab->size - slab->offset >= GUM_EXEC_BLOCK_MIN_SIZE)
    {
        GumExecBlock * block = (GumExecBlock *) (slab->data + slab->offset);

        block->ctx = ctx;
        block->slab = slab;

        block->code_begin = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (slab->data +
                                                                slab->offset + sizeof (GumExecBlock)));
        block->code_end = block->code_begin;

        block->state = GUM_EXEC_NORMAL;
        block->recycle_count = 0;
        block->has_call_to_excluded_range = FALSE;

        slab->offset += block->code_begin - (slab->data + slab->offset);
#ifdef ENABLE_DEBUG
        g_print("gum_exec_block_new - slab->size - slab->offset >= GUM_EXEC_BLOCK_MIN_SIZE\n");
        printf("data: %p, offset: %d, size GumExecBlock: %d\n", slab->data, slab->offset, sizeof (GumExecBlock));
        printf("block->code_begin: %p\n", block->code_begin);
#endif
        return block;
    }

    if (ctx->stalker->priv->trust_threshold < 0)
    {
#ifdef ENABLE_DEBUG
        g_print("gum_exec_block_new - ctx->stalker->priv->trust_threshold < 0\n");
#endif
        ctx->code_slab->offset = 0;
        return gum_exec_block_new (ctx);
    }

    slab = gum_alloc_n_pages (GUM_CODE_SLAB_SIZE_IN_PAGES, GUM_PAGE_RWX);
    slab->data = (guint8 *) (slab + 1);
    slab->offset = 0;
    slab->size = (GUM_CODE_SLAB_SIZE_IN_PAGES * ctx->stalker->priv->page_size)
                 - sizeof (GumSlab);
    slab->next = ctx->code_slab;
    ctx->code_slab = slab;

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_new - return gum_exec_block_new (ctx)\n");
#endif
    return gum_exec_block_new (ctx);
}

static GumExecBlock *
gum_exec_block_obtain (GumExecCtx * ctx,
                       gpointer real_address,
                       gpointer * code_address_ptr)
{
    GumExecBlock * block;

    block = gum_metal_hash_table_lookup (ctx->mappings, real_address);
    if (block != NULL)
        *code_address_ptr = block->code_begin;

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_obtain - exit\n");
    printf("code_address_ptr: %p\n", code_address_ptr);
    printf("code_address: %p\n", *code_address_ptr);
#endif
    return block;
}


static gboolean
gum_exec_block_is_full (GumExecBlock * block)
{
    guint8 * slab_end = block->slab->data + block->slab->size;
    return slab_end - block->code_end < GUM_EXEC_BLOCK_MIN_SIZE;
}

static void
gum_exec_block_commit (GumExecBlock * block)
{
    guint real_size;
    guint8 * aligned_end;

    real_size = block->real_end - block->real_begin;
    block->real_snapshot = block->code_end;
    memcpy (block->real_snapshot, block->real_begin, real_size);
    block->slab->offset += real_size;

    aligned_end = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (block->real_snapshot +
                                                      real_size));
    block->slab->offset += aligned_end - block->code_begin;
}

static void
gum_exec_block_backpatch_call (GumExecBlock * block,
                               gpointer code_start,
                               GumPrologType opened_prolog,
                               gpointer target_address,
                               gpointer ret_real_address,
                               gpointer ret_code_address)
{

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_backpatch_call - enter\n");
    printf("code_start: %p\n", code_start);
    printf("opened_prolog: %d\n", opened_prolog);
    printf("target_address: %p\n", target_address);
    printf("ret_real_address: %p\n", ret_real_address);
    printf("ret_code_address: %p\n", ret_code_address);
#endif

    GumExecCtx * ctx = block->ctx;

    if (ctx->state == GUM_EXEC_CTX_ACTIVE &&
        block->recycle_count >= ctx->stalker->priv->trust_threshold)
    {

#ifdef ENABLE_DEBUG
        g_print("\t - ctx->state == GUM_EXEC_CTX_ACTIVE && block->recycle_count >= ctx->stalker->priv->trust_threshold\n");
#endif

        GumArm64Writer * cw = &ctx->code_writer;
        gconstpointer beach_label = cw->code + 1;

        gum_arm64_writer_reset (cw, code_start);

        if (opened_prolog == GUM_PROLOG_NONE)
        {
            gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X14, ARM64_REG_X15);
            gum_arm64_writer_put_instruction(cw, 0xD53B420F);//MRS X15, NZCV
            gum_arm64_writer_put_instruction(cw, 0xF81F0FEF);//str x15, [sp,#-16]!
        }

        gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X14, GUM_ADDRESS (&block->ctx->current_frame));
        //gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_REG_XCX, GUM_ADDRESS (&block->ctx->current_frame));

        gum_arm64_writer_put_sub_reg_reg_imm(cw, ARM64_REG_X15, ARM64_REG_X14, block->ctx->stalker->priv->page_size - 1);
        //gum_x86_writer_put_test_reg_u32 (cw, GUM_REG_XCX,block->ctx->stalker->priv->page_size - 1);
#ifdef ENABLE_DEBUG
        printf("\t>b to beach_label if &block->ctx->current_frame(%p) - [block->ctx->stalker->priv->page_size - 1(%p)] = 0",
               GUM_ADDRESS (&block->ctx->current_frame), block->ctx->stalker->priv->page_size - 1);
#endif
        gum_arm64_writer_put_cbz_reg_label(cw, ARM64_REG_X15, beach_label);
        //gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JZ, beach_label, GUM_UNLIKELY);

#ifdef ENABLE_DEBUG
        printf("\t>save GumExecFrame(?) in &block->ctx->current_frame: %p", GUM_ADDRESS (&block->ctx->current_frame));
#endif
        gum_arm64_writer_put_sub_reg_reg_imm(cw, ARM64_REG_X14, ARM64_REG_X14, sizeof (GumExecFrame));
        //gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XCX, sizeof (GumExecFrame));
        gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X15, GUM_ADDRESS (&block->ctx->current_frame));
        gum_arm64_writer_put_str_reg_reg_offset(cw, ARM64_REG_X14, ARM64_REG_X15, 0);
        //gum_x86_writer_put_mov_near_ptr_reg (cw, GUM_ADDRESS (&block->ctx->current_frame), GUM_REG_XCX);

#ifdef ENABLE_DEBUG
        printf("\t>save in GumExecFrame(?) ret_real_address: %p", ret_real_address);
#endif
        gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X15, GUM_ADDRESS (ret_real_address));
        //gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX, GUM_ADDRESS (ret_real_address));
        gum_arm64_writer_put_str_reg_reg_offset(cw, ARM64_REG_X15, ARM64_REG_X14, 0);
        //gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_REG_XCX, GUM_REG_XAX);

#ifdef ENABLE_DEBUG
        printf("\t>save in G_STRUCT_OFFSET (GumCpuContext, sp)(?) ret_code_address: %p", ret_code_address);
#endif
        gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X15, GUM_ADDRESS (ret_code_address));
        //gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX, GUM_ADDRESS (ret_code_address));
        gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X15, ARM64_REG_X14, G_STRUCT_OFFSET (GumCpuContext, sp));
        //gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_REG_XCX, G_STRUCT_OFFSET (GumExecFrame, code_address), GUM_REG_XAX);

#ifdef ENABLE_DEBUG
        g_print("\t>label beach_label");
#endif
        gum_arm64_writer_put_label (cw, beach_label);//gum_x86_writer_put_label (cw, beach_label);

        if (opened_prolog == GUM_PROLOG_NONE)
        {
            gum_arm64_writer_put_instruction(cw, 0xF84107EF); //ldr x15, [sp],#16
            gum_arm64_writer_put_instruction(cw, 0xD51B420F);//msr NZCV, x15
            gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X14, ARM64_REG_X15);
        }
        else
        {
            gum_exec_ctx_write_epilog (block->ctx, opened_prolog, cw);
        }

        gum_arm64_writer_put_instruction(cw, 0xF81F0FEF);//str x15, [sp,#-16]!
        //gum_x86_writer_put_push_reg (cw, GUM_REG_XAX);

#ifdef ENABLE_DEBUG
        printf("\t>b to ret_real_address: %p");
#endif
        gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X30, GUM_ADDRESS (ret_real_address));
        //gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XAX, GUM_ADDRESS (ret_real_address));

        //TODO controlla dove va a finire sta roba!
        /*
            str x14, [sp,#-16]! F81F0FEE
            MOV X15, X14        AA0E03EF
            LDR X14, [sp]       F94003EE
            STR X15, [sp]       F90003EF
        */
        //gum_arm64_writer_put_instruction(cw, 0xAA0E03EF);
        //gum_arm64_writer_put_instruction(cw, 0xF94003EE);
        //gum_arm64_writer_put_instruction(cw, 0xF90003EF);
        //gum_x86_writer_put_xchg_reg_reg_ptr (cw, GUM_REG_XAX, GUM_REG_XSP);

        gum_arm64_writer_put_branch_address(cw, target_address);
        //gum_arm64_writer_put_b_imm(cw, target_address);
        // gum_x86_writer_put_jmp (cw, target_address);
        gum_arm64_writer_flush (cw);

    }
#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_backpatch_call - end \n");
#endif
}

static void
gum_exec_block_backpatch_jmp (GumExecBlock * block,
                              gpointer code_start,
                              GumPrologType opened_prolog,
                              gpointer target_address)
{

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_backpatch_jmp - enter\n");
    printf("code_start: %p\n", code_start);
    printf("target_address: %p\n", target_address);
#endif

    GumExecCtx * ctx = block->ctx;

    if (ctx->state == GUM_EXEC_CTX_ACTIVE &&
        block->recycle_count >= ctx->stalker->priv->trust_threshold)
    {
        GumArm64Writer * cw = &ctx->code_writer;

        gum_arm64_writer_reset (cw, code_start);

        if (opened_prolog != GUM_PROLOG_NONE)
        {
            gum_exec_ctx_write_epilog (block->ctx, opened_prolog, cw);
        }

        gum_arm64_writer_put_branch_address (cw, target_address);
        //gum_arm64_writer_put_b_imm (cw, target_address);
        //gum_x86_writer_put_jmp (cw, target_address);
        gum_arm64_writer_flush (cw);
    }

}

static void
gum_exec_block_backpatch_ret (GumExecBlock * block,
                              gpointer code_start,
                              gpointer target_address)
{
#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_backpatch_ret - enter");
    printf("code_start: %p", code_start);
    printf("target_address: %p", target_address);
#endif

    if (block != NULL) /* when we just unfollowed */
    {
        GumExecCtx * ctx = block->ctx;

        if (ctx->state == GUM_EXEC_CTX_ACTIVE &&
            block->recycle_count >= ctx->stalker->priv->trust_threshold)
        {
            GumArm64Writer * cw = &ctx->code_writer;

            gum_arm64_writer_reset (cw, code_start);
            gum_arm64_writer_put_branch_address (cw, target_address);
            //gum_arm64_writer_put_b_imm (cw, target_address);
            gum_arm64_writer_flush (cw);
        }
    }
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_branch_insn (GumExecBlock * block,
                                       GumGeneratorContext * gc)
{

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_virtualize_branch_insn - enter\n");
#endif

    GumInstruction * insn = gc->instruction;
    GumArm64Writer * cw = gc->code_writer;
    gboolean is_conditional;
    cs_arm64 * arm64 = &insn->ci->detail->arm64;
    cs_arm64_op * op = &arm64->operands[0];
    arm64_cc cc = arm64->cc;
    GumBranchTarget target = { 0, };

    is_conditional = (insn->ci->id == ARM64_INS_CBZ) ||
            (insn->ci->id == ARM64_INS_CBNZ) ||
            (insn->ci->id == ARM64_INS_TBZ) ||
            (insn->ci->id == ARM64_INS_TBNZ) ||
            (insn->ci->id == ARM64_INS_B && cc != ARM64_CC_INVALID);

    target.origin_ip = insn->end;
#ifdef ENABLE_DEBUG
    printf("\tconditional: %s\n", is_conditional?"yes":"no");
    printf("\ttarget.origin_ip = insn->end: %p\n", target.origin_ip);
#endif

    if (insn->ci->id == ARM64_INS_BL || insn->ci->id == ARM64_INS_B){

        g_assert(op->type == ARM64_OP_IMM);
#ifdef ENABLE_DEBUG
        printf("gum_exec_block_virtualize_branch_insn - BL & %sconditonal B\n", is_conditional?"":"in");
        printf("\top->imm: %p\n", op->imm);
        printf("\tinsn->ci->address: %p\n", insn->ci->address);
#endif
        target.absolute_address = GSIZE_TO_POINTER (op->imm);
        target.is_indirect = FALSE;
        target.base = ARM64_REG_INVALID;
        target.index = ARM64_REG_INVALID;
        target.disp = 0;
    }
    else if (insn->ci->id == ARM64_INS_BLR || insn->ci->id == ARM64_INS_BR)
    {
        g_assert(op->type == ARM64_OP_REG);
#ifdef ENABLE_DEBUG
        printf("gum_exec_block_virtualize_branch_insn - BLR & %sconditonal BR\n", is_conditional?"":"in");
        printf("\ttarget.base: %d\n", op->reg);
#endif
        target.is_indirect = FALSE;
        target.base = op->reg;
        target.index = ARM64_REG_INVALID;
        target.disp = 0;
    }
    else if(insn->ci->id == ARM64_INS_CBZ || insn->ci->id == ARM64_INS_CBNZ){

        cs_arm64_op * op2 = &arm64->operands[1];

        g_assert(op->type == ARM64_OP_REG);
        g_assert(op2->type == ARM64_OP_IMM);
#ifdef ENABLE_DEBUG
        if(insn->ci->id == ARM64_INS_CBZ) g_print("gum_exec_block_virtualize_branch_insn - CBZ\n");
        else g_print("gum_exec_block_virtualize_branch_insn - CBNZ\n");
        printf("\ttarget.absolute_address: %d\n", op2->imm);
#endif

        target.is_indirect = FALSE;
        target.absolute_address = GSIZE_TO_POINTER (op2->imm);
        target.base = ARM64_REG_INVALID;
        target.index = ARM64_REG_INVALID;
        target.disp = 0;

    }
    else
    {
        g_assert_not_reached ();
    }

    if (insn->ci->id == ARM64_INS_BL || insn->ci->id == ARM64_INS_BLR)
    {
#ifdef ENABLE_DEBUG
        if (insn->ci->id == ARM64_INS_BL)
            g_print("gum_exec_block_virtualize_branch_insn - insn->ci->id == ARM64_INS_BL\n");
        else
            g_print("gum_exec_block_virtualize_branch_insn - insn->ci->id == ARM64_INS_BLR\n");
#endif

        gboolean target_is_excluded = FALSE;

        if ((block->ctx->sink_mask & GUM_CALL) != 0)
        {
#ifdef ENABLE_DEBUG
            g_print("\t - (block->ctx->sink_mask & GUM_CALL) != 0\n");
#endif
            gum_exec_block_write_call_event_code (block, &target, gc, GUM_CODE_INTERRUPTIBLE);
        }

        if (block->ctx->stalker->priv->any_probes_attached){
#ifdef ENABLE_DEBUG
            g_print("\t - block->ctx->stalker->priv->any_probes_attached\n");
#endif
            gum_exec_block_write_call_probe_code (block, &target, gc);
        }

        if (!target.is_indirect && target.base == ARM64_REG_INVALID)
        {
#ifdef ENABLE_DEBUG
            g_print("\t - !target.is_indirect && target.base == ARM64_REG_INVALID\n");
#endif
            GArray * exclusions = block->ctx->stalker->priv->exclusions;
            guint i;

            for (i = 0; i != exclusions->len; i++)
            {
                GumMemoryRange * r = &g_array_index (exclusions, GumMemoryRange, i);
                if (GUM_MEMORY_RANGE_INCLUDES (r, GUM_ADDRESS (target.absolute_address)))
                {
                    target_is_excluded = TRUE;
                    break;
                }
            }
        }

        if (target_is_excluded)
        {
#ifdef ENABLE_DEBUG
            g_print("\t - target_is_excluded\n");
#endif
            block->has_call_to_excluded_range = TRUE;
            return GUM_REQUIRE_RELOCATION;
        }

        gum_arm64_relocator_skip_one(gc->relocator);

        gum_exec_block_write_call_invoke_code (block, &target, gc);

    }else if(insn->ci->id == ARM64_INS_CBZ || insn->ci->id == ARM64_INS_CBNZ
            || insn->ci->id == ARM64_INS_B){

        gpointer is_false;

        gum_arm64_relocator_skip_one (gc->relocator);

        is_false = GUINT_TO_POINTER ((GPOINTER_TO_UINT (insn->begin) << 16) | 0xbeef);

        if (is_conditional)
        {
            g_assert (!target.is_indirect);

            gum_exec_block_close_prolog (block, gc);

            //jump to is_false if is_false
            if (insn->ci->id == ARM64_INS_CBZ){
                gum_arm64_writer_put_cbnz_reg_label (cw, op->reg,  is_false);
            } else if (insn->ci->id == ARM64_INS_CBNZ){
                gum_arm64_writer_put_cbz_reg_label(cw, op->reg,  is_false);
            }else if(insn->ci->id == ARM64_INS_B){

                g_assert(cc != ARM64_CC_INVALID);
                g_assert(cc > ARM64_CC_INVALID);
                g_assert(cc <= ARM64_CC_NV);

                arm64_cc not_cc = cc + 2*(cc%2) -1;

#ifdef ENABLE_DEBUG
                printf("cc (%d) and not_cc (%d)",cc, not_cc);
#endif

                gum_arm64_writer_put_b_cond_label (cw, not_cc, is_false);


            }else g_assert_not_reached ();

        }

        gum_exec_block_write_jmp_transfer_code (block, &target, gc);

        if (is_conditional)
        {
            GumBranchTarget cond_target = { 0, };

            cond_target.is_indirect = FALSE;
            cond_target.absolute_address = insn->end;


            gum_arm64_writer_put_label (cw, is_false);

            gum_exec_block_write_jmp_transfer_code (block, &cond_target, gc);
        }


    } else{

        g_assert("gum_exec_block_virtualize_branch_insn" == "not implemented");

    }

    return GUM_REQUIRE_NOTHING;
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_ret_insn (GumExecBlock * block,
                                    GumGeneratorContext * gc)
{

    if ((block->ctx->sink_mask & GUM_RET) != 0)
        gum_exec_block_write_ret_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);

    gum_arm64_relocator_skip_one(gc->relocator);
    gum_exec_block_write_ret_transfer_code (block, gc);

    return GUM_REQUIRE_NOTHING;


}

static GumVirtualizationRequirements
gum_exec_block_virtualize_sysenter_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
}


static void
gum_exec_block_write_call_invoke_code (GumExecBlock * block,
                                       const GumBranchTarget * target,
                                       GumGeneratorContext * gc)
{
#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_call_invoke_code - enter\n");
#endif
    gboolean can_backpatch;
    GumArm64Writer * cw = gc->code_writer;
    gpointer call_code_start;
    GumPrologType opened_prolog;
    gconstpointer perform_stack_push = cw->code + 1;
    gconstpointer skip_stack_push = cw->code + 2;
    gpointer ret_real_address;
    gpointer ret_code_address;

    call_code_start = cw->code;
    opened_prolog = gc->opened_prolog;

    /* We can backpatch if we have some trust and the call's target is static */
    can_backpatch = (block->ctx->stalker->priv->trust_threshold >= 0 &&
                     !target->is_indirect &&
                     target->base == ARM64_REG_INVALID);
    can_backpatch= false;

    gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

#ifdef ENABLE_DEBUG
    printf("\t> gum_exec_ctx_replace_current_block_with\n\t\t(block->ctx: %p,\n\t\ttarget->absolute_address: %p|%d)\n",
            block->ctx, target->absolute_address, target->base);
#endif

    /* generate code for the target */
    // get the target
    gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
    gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X14, ARM64_REG_X15);

    // create new block for the target
    gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X29, ARM64_REG_X30);
    gum_arm64_writer_put_call_address_with_arguments(cw,
                                                     GUM_FUNCPTR_TO_POINTER (gum_exec_ctx_replace_current_block_with), 2,
                                                     GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
                                                     GUM_ARG_REGISTER, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X29, ARM64_REG_X30);

    gum_exec_block_close_prolog (block, gc);

#ifdef ENABLE_DEBUG
    printf("> b to address pointed by block->ctx->resume_at: %p\n", &block->ctx->resume_at);
    printf("\t> gc->instruction->end (saving in placeholder : %p\n", gc->instruction->end);
#endif
    // we need to save the return address outside the open-close prolog
    gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X30, GUM_ADDRESS (gc->instruction->end));

    /* execute the generated code */
    //todo: we clobbers registers here and can't use reuse ARM64_STALKER_REG_CTX
    gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X16, GUM_ADDRESS (&block->ctx->resume_at));
    gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X17, ARM64_REG_X16, 0);
    gum_arm64_writer_put_br_reg(cw, ARM64_REG_X17);

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_call_invoke_code - exit\n");
#endif


}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        GumGeneratorContext * gc){

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_jmp_transfer_code - enter");
#endif

    GumArm64Writer * cw = gc->code_writer;
    guint8 * code_start;
    GumPrologType opened_prolog;

    code_start = cw->code;
    opened_prolog = gc->opened_prolog;

    gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

    gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
    gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X14, ARM64_REG_X15);

    gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X29, ARM64_REG_X30);
    gum_arm64_writer_put_call_address_with_arguments(cw,
                                                     GUM_FUNCPTR_TO_POINTER (gum_exec_ctx_replace_current_block_with), 2,
                                                     GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
                                                     GUM_ARG_REGISTER, ARM64_REG_X15);
    gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X29, ARM64_REG_X30);
    gum_arm64_writer_put_mov_reg_reg(cw, ARM64_REG_X15, ARM64_REG_X0);


    if (false && block->ctx->stalker->priv->trust_threshold >= 0 &&
        !target->is_indirect &&
        target->base == ARM64_REG_INVALID)
    {
        gum_arm64_writer_put_call_address_with_arguments(cw,
                                                         GUM_FUNCPTR_TO_POINTER (gum_exec_block_backpatch_jmp), 4,
                                                         GUM_ARG_ADDRESS, block,
                                                         GUM_ARG_ADDRESS, code_start,
                                                         GUM_ARG_ADDRESS, GSIZE_TO_POINTER (opened_prolog),
                                                         GUM_ARG_REGISTER, ARM64_REG_X15);
/*
        gum_x86_writer_put_call_with_arguments (cw,
                                                GUM_FUNCPTR_TO_POINTER (gum_exec_block_backpatch_jmp), 4,
                                                GUM_ARG_POINTER, block,
                                                GUM_ARG_POINTER, code_start,
                                                GUM_ARG_POINTER, GSIZE_TO_POINTER (opened_prolog),
                                                GUM_ARG_REGISTER, GUM_REG_XAX);
*/
    }



    gum_exec_block_close_prolog (block, gc);

    gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X16, GUM_ADDRESS (&block->ctx->resume_at));
    gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X17, ARM64_REG_X16, 0);
    gum_arm64_writer_put_br_reg(cw, ARM64_REG_X17);
#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_jmp_transfer_code - exit\n");
    printf("> b to address pointed by block->ctx->resume_at: %p\n", &block->ctx->resume_at);
#endif

}

static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        GumGeneratorContext * gc){

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_ret_transfer_code - enter\n");
#endif

    GumArm64Writer * cw = gc->code_writer;
    gconstpointer resolve_dynamically_label = cw->code;

    gum_exec_block_close_prolog (block, gc);
    gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

    gum_arm64_writer_put_call_address_with_arguments(cw,
                                                     GUM_FUNCPTR_TO_POINTER (gum_exec_ctx_replace_current_block_with), 2,
                                                     GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
                                                     GUM_ARG_REGISTER, ARM64_REG_X30);



    gum_exec_block_close_prolog (block, gc);

    gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X16, GUM_ADDRESS (&block->ctx->resume_at));
    gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X17, ARM64_REG_X16, 0);
    gum_arm64_writer_put_br_reg(cw, ARM64_REG_X17);

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_ret_transfer_code - exit\n");
#endif

}

static void
gum_exec_block_write_single_step_transfer_code (GumExecBlock * block,
                                                GumGeneratorContext * gc)
{

    g_assert(""=="to check...");

    gum_arm64_writer_put_push_reg_reg(gc->code_writer, ARM64_REG_X14, ARM64_REG_X15);
    gum_arm64_writer_put_instruction(gc->code_writer, 0xD53B420F);//MRS X15, NZCV
    gum_arm64_writer_put_instruction(gc->code_writer, 0xF81F0FEF);//str x15, [sp,#-16]!

    gum_arm64_writer_put_ldr_reg_address(gc->code_writer, ARM64_REG_X15, GUM_ADDRESS (&block->state));
    gum_arm64_writer_put_sub_reg_reg_imm(gc->code_writer, ARM64_REG_X14, ARM64_REG_X14, 0);
    gum_arm64_writer_put_add_reg_reg_imm(gc->code_writer, ARM64_REG_X14, ARM64_REG_X14, GUM_EXEC_SINGLE_STEPPING_ON_CALL);
    gum_arm64_writer_put_str_reg_reg_offset(gc->code_writer, ARM64_REG_X14, ARM64_REG_X15, 0);

    /*
     * LDR X15, [sp], #0
     * ORR X15, X5, 0x100
     * STR X15, [sp], #0
     */
    gum_arm64_writer_put_instruction(gc->code_writer, 0xF84007EF);
    gum_arm64_writer_put_instruction(gc->code_writer, 0xB27801EF);
    gum_arm64_writer_put_instruction(gc->code_writer, 0xF80007EF);

    gum_arm64_writer_put_instruction(gc->code_writer, 0xF84107EF); //ldr x15, [sp],#16
    gum_arm64_writer_put_instruction(gc->code_writer, 0xD51B420F);//msr NZCV, x15
    gum_arm64_writer_put_pop_reg_reg(gc->code_writer, ARM64_REG_X14, ARM64_REG_X15);

    gum_arm64_writer_put_branch_address(gc->code_writer, gc->instruction->begin);
}

static void
gum_exec_block_write_call_event_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc){

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_call_event_code - enter\n");
#endif

    GumArm64Writer * cw = gc->code_writer;

    gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

    gum_exec_block_write_event_init_code (block, GUM_CALL, gc);

    // save the location of the call event
    gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X14, GUM_ADDRESS (gc->instruction->begin));
    STALKER_STORE_REG_INTO_CTX_WITH_AO(ARM64_REG_X14, tmp_event, G_STRUCT_OFFSET (GumCallEvent, location));

    // save the target of the call event
    gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc);
    // previous function changes X15
    gum_arm64_writer_put_pop_reg_reg(cw, ARM64_REG_X14, ARM64_REG_X14);

    STALKER_STORE_REG_INTO_CTX_WITH_AO(ARM64_REG_X14, tmp_event, G_STRUCT_OFFSET (GumCallEvent, target));


    // save the call depth TODO better understand...
    gum_arm64_writer_put_ldr_reg_u64(cw, ARM64_REG_X14, 4);
    STALKER_STORE_REG_INTO_CTX_WITH_AO(ARM64_REG_X14, tmp_event, G_STRUCT_OFFSET (GumCallEvent, depth));


    gum_exec_block_write_event_submit_code (block, gc, cc);

}

static void
gum_exec_block_write_ret_event_code (GumExecBlock * block,
                                     GumGeneratorContext * gc,
                                     GumCodeContext cc)
{

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_ret_event_code - enter\n");
#endif

    GumArm64Writer * cw = gc->code_writer;

    gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

    gum_exec_block_write_event_init_code (block, GUM_RET, gc);

    // save the location of the call event
    gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X14, GUM_ADDRESS (gc->instruction->begin));
    STALKER_STORE_REG_INTO_CTX_WITH_AO(ARM64_REG_X14, tmp_event, G_STRUCT_OFFSET (GumRetEvent, location));

    // save return address of the ret (its target)
    STALKER_STORE_REG_INTO_CTX_WITH_AO(ARM64_REG_X30, tmp_event, G_STRUCT_OFFSET (GumRetEvent, target));

    // save the call depth TODO better understand...
    gum_arm64_writer_put_ldr_reg_u64(cw, ARM64_REG_X14, 4);
    STALKER_STORE_REG_INTO_CTX_WITH_AO(ARM64_REG_X14, tmp_event, G_STRUCT_OFFSET (GumRetEvent, depth));

    gum_exec_block_write_event_submit_code (block, gc, cc);

}

static void
gum_exec_block_write_exec_event_code (GumExecBlock * block,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc){
#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_exec_event_code - enter\n");
#endif

    GumArm64Writer * cw = gc->code_writer;

    gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc);

    gum_exec_block_write_event_init_code (block, GUM_EXEC, gc);

    // save location
    gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X14, GUM_ADDRESS (gc->instruction->begin));
    STALKER_STORE_REG_INTO_CTX_WITH_AO(ARM64_REG_X14, tmp_event, G_STRUCT_OFFSET (GumExecEvent, location));

    gum_exec_block_write_event_submit_code (block, gc, cc);

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_exec_event_code - exit\n");
#endif

}

static void
gum_exec_block_write_event_init_code (GumExecBlock * block,
                                      GumEventType type,
                                      GumGeneratorContext * gc){

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_event_init_code - enter\n");
#endif

    GumArm64Writer * cw = gc->code_writer;

    // save the type of event
    gum_arm64_writer_put_instruction(cw, 0xCB0E01CE);
    gum_arm64_writer_put_add_reg_reg_imm(cw, ARM64_REG_X14, ARM64_REG_X14, type);
    //gum_arm64_writer_put_ldr_reg_u64(cw, ARM64_REG_X14, type);
    STALKER_STORE_REG_INTO_CTX_WITH_AO(ARM64_REG_X14, tmp_event, G_STRUCT_OFFSET (GumAnyEvent, type));

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_event_init_code - exit\n");
#endif

}

static void
gum_exec_block_write_event_submit_code (GumExecBlock * block,
                                        GumGeneratorContext * gc,
                                        GumCodeContext cc)
{

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_event_submit_code - enter\n");
    g_print("gum_exec_block_write_event_submit_code - enter\n");
#endif

    GumExecCtx * ctx = block->ctx;
    GumArm64Writer * cw = gc->code_writer;
    gconstpointer beach_label = cw->code + 1;
    GumPrologType opened_prolog;

    gum_arm64_writer_put_push_all_registers(cw);
    gum_arm64_writer_put_add_reg_reg_imm(cw, ARM64_REG_X15, ARM64_STALKER_REG_CTX, G_STRUCT_OFFSET (GumExecCtx, tmp_event));
    gum_arm64_writer_put_call_address_with_arguments(cw,
                                             block->ctx->sink_process_impl, 2,
                                             GUM_ARG_ADDRESS, block->ctx->sink,
                                             GUM_ARG_REGISTER, ARM64_REG_X15);
    gum_arm64_writer_put_pop_all_registers(cw);

    if (cc == GUM_CODE_INTERRUPTIBLE)
    {
        /* check if we've been asked to unfollow */
        STALKER_LOAD_REG_FROM_CTX(ARM64_REG_X14, state);
        gum_arm64_writer_put_sub_reg_reg_imm(cw, ARM64_REG_X14, ARM64_REG_X14, GUM_EXEC_CTX_UNFOLLOW_PENDING);
        gum_arm64_writer_put_cbnz_reg_label(cw, ARM64_REG_X14, beach_label);

        //gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_REG_EAX, GUM_ADDRESS (&ctx->state));
        //gum_x86_writer_put_cmp_reg_i32 (cw, GUM_REG_EAX, GUM_EXEC_CTX_UNFOLLOW_PENDING);
        //gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JNZ, beach_label, GUM_LIKELY);

        gum_arm64_writer_put_call_address_with_arguments(cw,
                                                 GUM_FUNCPTR_TO_POINTER (gum_exec_ctx_unfollow), 2,
                                                 GUM_ARG_ADDRESS, ctx,
                                                 GUM_ARG_ADDRESS, gc->instruction->begin);
        /*gum_x86_writer_put_call_with_arguments (cw,
                                                GUM_FUNCPTR_TO_POINTER (gum_exec_ctx_unfollow), 2,
                                                GUM_ARG_POINTER, ctx,
                                                GUM_ARG_POINTER, gc->instruction->begin);*/
        opened_prolog = gc->opened_prolog;
        gum_exec_block_close_prolog (block, gc);
        gc->opened_prolog = opened_prolog;

        gum_arm64_writer_put_push_reg_reg(cw, ARM64_REG_X16, ARM64_REG_X17);
        gum_arm64_writer_put_ldr_reg_address(cw, ARM64_REG_X16, GUM_ADDRESS (&block->ctx->resume_at));
        gum_arm64_writer_put_ldr_reg_reg_offset(cw, ARM64_REG_X17, ARM64_REG_X16, 0);
        gum_arm64_writer_put_br_reg(cw, ARM64_REG_X17);
        //gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (&ctx->resume_at));

        gum_arm64_writer_put_label(cw, beach_label);
        //gum_x86_writer_put_label (cw, beach_label);
    }

#ifdef ENABLE_DEBUG
    g_print("gum_exec_block_write_event_submit_code - exit\n");
#endif


}

static void
gum_exec_block_invoke_call_probes_for_target (GumExecBlock * block,
                                              gpointer target_address,
                                              GumCpuContext * cpu_context){}

static void
gum_exec_block_write_call_probe_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc){}

static void
gum_exec_block_open_prolog (GumExecBlock * block,
                            GumPrologType type,
                            GumGeneratorContext * gc){
    if (gc->opened_prolog >= type)
        return;

    /* We don't want to handle this case for performance reasons */
    g_assert (gc->opened_prolog == GUM_PROLOG_NONE);

#ifdef ENABLE_DEBUG
    printf("+++ gum_exec_block_open_prolog - %d\n", type);
    printf("\tgc->instruction->begin (saved as ip) - %p\n", gc->instruction->begin);
#endif
    gc->opened_prolog = type;
    gum_exec_ctx_write_prolog (block->ctx, type, gc->instruction->begin, gc->code_writer);
}

static void
gum_exec_block_close_prolog (GumExecBlock * block,
                             GumGeneratorContext * gc){
    if (gc->opened_prolog == GUM_PROLOG_NONE)
        return;

    gum_exec_ctx_write_epilog (block->ctx, gc->opened_prolog, gc->code_writer);

#ifdef ENABLE_DEBUG
    printf("--- gum_exec_block_close_prolog - %d\n", gc->opened_prolog);
#endif
    gc->opened_prolog = GUM_PROLOG_NONE;

}

static void
gum_write_segment_prefix (uint8_t segment,
                          GumArm64Writer * cw){}
static GumArm64MetaReg
gum_cpu_meta_reg_from_real_reg (GumArm64MetaReg reg){}

static GumArm64MetaReg
gum_cpu_reg_from_capstone (arm64_reg reg){}