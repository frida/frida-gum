/*
 * Copyright (C) 2009-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2010 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_STALKER_H__
#define __GUM_STALKER_H__

#include <capstone.h>
#include <gum/arch-x86/gumx86writer.h>
#include <gum/arch-arm/gumarmwriter.h>
#include <gum/arch-arm/gumthumbwriter.h>
#include <gum/arch-arm64/gumarm64writer.h>
#include <gum/arch-mips/gummipswriter.h>
#include <gum/gumdefs.h>
#include <gum/gumeventsink.h>
#include <gum/gumprocess.h>

G_BEGIN_DECLS

#define GUM_TYPE_STALKER (gum_stalker_get_type ())
GUM_DECLARE_FINAL_TYPE (GumStalker, gum_stalker, GUM, STALKER, GObject)

#define GUM_TYPE_STALKER_TRANSFORMER (gum_stalker_transformer_get_type ())
GUM_DECLARE_INTERFACE (GumStalkerTransformer, gum_stalker_transformer, GUM,
    STALKER_TRANSFORMER, GObject)

#define GUM_TYPE_DEFAULT_STALKER_TRANSFORMER \
    (gum_default_stalker_transformer_get_type ())
GUM_DECLARE_FINAL_TYPE (GumDefaultStalkerTransformer,
    gum_default_stalker_transformer, GUM, DEFAULT_STALKER_TRANSFORMER,
    GObject)

#define GUM_TYPE_CALLBACK_STALKER_TRANSFORMER \
    (gum_callback_stalker_transformer_get_type ())
GUM_DECLARE_FINAL_TYPE (GumCallbackStalkerTransformer,
    gum_callback_stalker_transformer, GUM, CALLBACK_STALKER_TRANSFORMER,
    GObject)

#define GUM_TYPE_STALKER_OBSERVER (gum_stalker_observer_get_type ())
GUM_DECLARE_INTERFACE (GumStalkerObserver, gum_stalker_observer, GUM,
    STALKER_OBSERVER, GObject)

typedef struct _GumStalkerIterator GumStalkerIterator;
typedef struct _GumStalkerOutput GumStalkerOutput;
typedef struct _GumBackpatch GumBackpatch;
typedef struct _GumBackpatchInstruction GumBackpatchInstruction;
typedef void (* GumStalkerIncrementFunc) (GumStalkerObserver * self);
typedef void (* GumStalkerNotifyBackpatchFunc) (GumStalkerObserver * self,
    const GumBackpatch * backpatch, gsize size);
typedef void (* GumStalkerSwitchCallbackFunc) (GumStalkerObserver * self,
    gpointer start_address, const cs_insn * from_insn, gpointer * target);
typedef union _GumStalkerWriter GumStalkerWriter;
typedef void (* GumStalkerTransformerCallback) (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
typedef void (* GumStalkerCallout) (GumCpuContext * cpu_context,
    gpointer user_data);

typedef guint GumProbeId;
typedef struct _GumCallDetails GumCallDetails;
typedef void (* GumCallProbeCallback) (GumCallDetails * details,
    gpointer user_data);

#ifndef GUM_DIET

struct _GumStalkerTransformerInterface
{
  GTypeInterface parent;

  void (* transform_block) (GumStalkerTransformer * self,
      GumStalkerIterator * iterator, GumStalkerOutput * output);
};

struct _GumStalkerObserverInterface
{
  GTypeInterface parent;

  /* Common */
  GumStalkerIncrementFunc increment_total;

  GumStalkerIncrementFunc increment_call_imm;
  GumStalkerIncrementFunc increment_call_reg;

  /* x86 only */
  GumStalkerIncrementFunc increment_call_mem;

  /* Arm64 only */
  GumStalkerIncrementFunc increment_excluded_call_reg;

  /* x86 only */
  GumStalkerIncrementFunc increment_ret_slow_path;

  /* Arm64 only */
  GumStalkerIncrementFunc increment_ret;

  /* Common */
  GumStalkerIncrementFunc increment_post_call_invoke;
  GumStalkerIncrementFunc increment_excluded_call_imm;

  /* Common */
  GumStalkerIncrementFunc increment_jmp_imm;
  GumStalkerIncrementFunc increment_jmp_reg;

  /* x86 only */
  GumStalkerIncrementFunc increment_jmp_mem;
  GumStalkerIncrementFunc increment_jmp_cond_imm;
  GumStalkerIncrementFunc increment_jmp_cond_mem;
  GumStalkerIncrementFunc increment_jmp_cond_reg;
  GumStalkerIncrementFunc increment_jmp_cond_jcxz;

  /* Arm64 only */
  GumStalkerIncrementFunc increment_jmp_cond_cc;
  GumStalkerIncrementFunc increment_jmp_cond_cbz;
  GumStalkerIncrementFunc increment_jmp_cond_cbnz;
  GumStalkerIncrementFunc increment_jmp_cond_tbz;
  GumStalkerIncrementFunc increment_jmp_cond_tbnz;

  /* Common */
  GumStalkerIncrementFunc increment_jmp_continuation;

  /* x86 only */
  GumStalkerIncrementFunc increment_sysenter_slow_path;

  GumStalkerNotifyBackpatchFunc notify_backpatch;

  GumStalkerSwitchCallbackFunc switch_callback;
};

#endif

union _GumStalkerWriter
{
  gpointer instance;
  GumX86Writer * x86;
  GumArmWriter * arm;
  GumThumbWriter * thumb;
  GumArm64Writer * arm64;
  GumMipsWriter * mips;
};

struct _GumStalkerOutput
{
  GumStalkerWriter writer;
  GumInstructionEncoding encoding;
};

struct _GumCallDetails
{
  gpointer target_address;
  gpointer return_address;
  gpointer stack_data;
  GumCpuContext * cpu_context;
};

GUM_API gboolean gum_stalker_is_supported (void);

GUM_API GumStalker * gum_stalker_new (void);

GUM_API void gum_stalker_exclude (GumStalker * self,
    const GumMemoryRange * range);

GUM_API gint gum_stalker_get_trust_threshold (GumStalker * self);
GUM_API void gum_stalker_set_trust_threshold (GumStalker * self,
    gint trust_threshold);

GUM_API void gum_stalker_flush (GumStalker * self);
GUM_API void gum_stalker_stop (GumStalker * self);
GUM_API gboolean gum_stalker_garbage_collect (GumStalker * self);

GUM_API void gum_stalker_follow_me (GumStalker * self,
    GumStalkerTransformer * transformer, GumEventSink * sink);
GUM_API void gum_stalker_unfollow_me (GumStalker * self);
GUM_API gboolean gum_stalker_is_following_me (GumStalker * self);

GUM_API void gum_stalker_follow (GumStalker * self, GumThreadId thread_id,
    GumStalkerTransformer * transformer, GumEventSink * sink);
GUM_API void gum_stalker_unfollow (GumStalker * self, GumThreadId thread_id);

GUM_API void gum_stalker_activate (GumStalker * self, gconstpointer target);
GUM_API void gum_stalker_deactivate (GumStalker * self);

GUM_API void gum_stalker_set_observer (GumStalker * self,
    GumStalkerObserver * observer);

/**
 * gum_stalker_prefetch:
 *
 * This API is intended for use during fuzzing scenarios such as AFL forkserver.
 * It allows for the child to feed back the addresses of instrumented blocks to
 * the parent so that the next time a child is forked from the parent, it will
 * already inherit the instrumented block rather than having to re-instrument
 * every basic block again from scratch.
 *
 * This API has the following caveats:
 *
 * 1. This API MUST be called from the thread which will be executed in the
 *    child. Since blocks are cached in the GumExecCtx which is stored on a
 *    per-thread basis and accessed through Thread Local Storage, it is not
 *    possible to prefetch blocks into the cache of another thread.
 *
 * 2. This API should be called after gum_stalker_follow_me(). It is likely that
 *    the parent will wish to call gum_stalker_deactivate() immediately after
 *    following. Subsequently, gum_stalker_activate() can be called within the
 *    child after it is forked to start stalking the thread once more. The child
 *    can then communicate newly discovered basic blocks back to the parent via
 *    inter-process communications. The parent can then call
 *    gum_stalker_prefetch() to instrument those blocks before forking the next
 *    child. As a result of the fork, the child inherits a deactivated Stalker
 *    instance, thus both parent and child should release their Stalker
 *    instances upon completion if required.
 *
 * 3. Note that gum_stalker_activate() takes a `target` pointer which is used to
 *    allow Stalker to be reactivated whilst executing in an excluded range and
 *    guarantee that the thread is followed until the “activation target”
 *    address is reached. Typically for e.g. a fuzzer the target would be the
 *    function you're about to hit with inputs. When this target isn't known,
 *    the simplest solution to this is to define an empty function (marked as
 *    non-inlineable) and then subsequently call it immediately after activation
 *    to return Stalker to its normal behavior. It is important that `target` is
 *    at the start of a basic block, otherwise Stalker will not detect it.
 *    Failure to do so may mean that Stalker continues to follow the thread into
 *    code which it should not, including any calls to Stalker itself. Thus care
 *    should be taken to ensure that the function is not inlined, or optimized
 *    away by the compiler.
 *
 *    __attribute__ ((noinline))
 *    static void
 *    activation_target (void)
 *    {
        // Avoid calls being optimized out
 *      asm ("");
 *    }
 *
 * 4. Note that since both parent and child have an identical Stalker instance,
 *    they each have the exact same Transformer. Since this Transformer will
 *    be used both to generate blocks to execute in the child and to prefetch
 *    blocks in the parent, care should be taken to identify in which scenario
 *    the transformer is operating. The parent will likely also transform and
 *    execute a few blocks even if it is deactivated immediately afterwards.
 *    Thus care should also be taken when any callouts are executed to determine
 *    whether they are running in the parent or child context.
 *
 * 5. For optimal performance, the recycle_count should be set to the same value
 *    as gum_stalker_get_trust_threshold(). Unless the trust threshold is set to
 *    `-1` or `0`. When adding instrumented blocks into the cache, Stalker also
 *    retains a copy of the original bytes of the code which was instrumented.
 *    When recalling blocks from the cache, this is compared in order to detect
 *    self-modifying code. If the block is the same, then the recycle_count is
 *    incremented. The trust threshold sets the limit of how many times a block
 *    should be identical (e.g. the code has not been modified) before this
 *    comparison can be omitted. Thus when prefetching, we can also set the
 *    recycle_count to control whether this comparison takes place. When the
 *    trust threshold is less than `1`, the block_recycle count has not effect.
 *
 * 6. This API does not change the trust threshold as it is a global setting
 *    which affects all Stalker sessions running on all threads.
 *
 * 7. It is inadvisable to prefetch self-modifying code blocks, since it will
 *    mean a single static instrumented block will always be used when it is
 *    executed. The detection of self-modifying code in the child is left to the
 *    user, just as the user is free to choose which blocks to prefetch by
 *    calling the API. It may also be helpful to avoid sending the same block
 *    address to be prefetched to the parent multiple times to reduce I/O
 *    required via IPC, particularly if the same block is executed multiple
 *    times. If you are fuzzing self-modifying code, then your day is probably
 *    already going badly.
 *
 * The following is provided as an example workflow for initializing a fork
 * server based fuzzer:
 *
 *    p -> setup IPC mechanism with child (e.g. pipe)
 *    p -> create custom Transformer to send address of instrumented block to
 *         parent via IPC. Transformer should be inert until latched. Callouts
 *         should still be generated as required when not latched, but should
 *         themselves be inert until latched.
 *    p -> gum_stalker_follow_me ()
 *    p -> gum_stalker_deactivate ()
 *
 *    BEGIN LOOP:
 *
 *    p -> fork ()
 *    p -> waitpid ()
 *
 *    c -> set latch to trigger Transformer (note that this affects only the
 *         child process).
 *    c -> gum_stalker_activate (activation_target)
 *    c -> activation_target ()
 *    c -> <RUN CODE UNDER TEST HERE>
 *    c -> gum_stalker_unfollow_me () or simply exit ()
 *
 *    p -> gum_stalker_set_trust_threshold (0)
 *    p -> gum_stalker_prefetch (x) (n times for each)
 *    p -> gum_stalker_set_trust_threshold (n)
 *
 *    END LOOP:
 */
GUM_API void gum_stalker_prefetch (GumStalker * self, gconstpointer address,
    gint recycle_count);
GUM_API void gum_stalker_prefetch_backpatch (GumStalker * self,
    const GumBackpatch * notification);

GUM_API void gum_stalker_invalidate (GumStalker * self, gconstpointer address);
GUM_API void gum_stalker_invalidate_for_thread (GumStalker * self,
    GumThreadId thread_id, gconstpointer address);

GUM_API GumProbeId gum_stalker_add_call_probe (GumStalker * self,
    gpointer target_address, GumCallProbeCallback callback, gpointer data,
    GDestroyNotify notify);
GUM_API void gum_stalker_remove_call_probe (GumStalker * self,
    GumProbeId id);

GUM_API GumStalkerTransformer * gum_stalker_transformer_make_default (void);
GUM_API GumStalkerTransformer * gum_stalker_transformer_make_from_callback (
    GumStalkerTransformerCallback callback, gpointer data,
    GDestroyNotify data_destroy);

GUM_API void gum_stalker_transformer_transform_block (
    GumStalkerTransformer * self, GumStalkerIterator * iterator,
    GumStalkerOutput * output);

GUM_API gboolean gum_stalker_iterator_next (GumStalkerIterator * self,
    const cs_insn ** insn);
GUM_API void gum_stalker_iterator_keep (GumStalkerIterator * self);
GUM_API void gum_stalker_iterator_put_callout (GumStalkerIterator * self,
    GumStalkerCallout callout, gpointer data, GDestroyNotify data_destroy);

#define GUM_DECLARE_OBSERVER_INCREMENT(name) \
    GUM_API void gum_stalker_observer_increment_##name ( \
        GumStalkerObserver * observer);

GUM_DECLARE_OBSERVER_INCREMENT (total)

GUM_DECLARE_OBSERVER_INCREMENT (call_imm)
GUM_DECLARE_OBSERVER_INCREMENT (call_reg)

GUM_DECLARE_OBSERVER_INCREMENT (call_mem)

GUM_DECLARE_OBSERVER_INCREMENT (excluded_call_reg)

GUM_DECLARE_OBSERVER_INCREMENT (ret_slow_path)

GUM_DECLARE_OBSERVER_INCREMENT (ret)

GUM_DECLARE_OBSERVER_INCREMENT (post_call_invoke)
GUM_DECLARE_OBSERVER_INCREMENT (excluded_call_imm)

GUM_DECLARE_OBSERVER_INCREMENT (jmp_imm)
GUM_DECLARE_OBSERVER_INCREMENT (jmp_reg)

GUM_DECLARE_OBSERVER_INCREMENT (jmp_mem)
GUM_DECLARE_OBSERVER_INCREMENT (jmp_cond_imm)
GUM_DECLARE_OBSERVER_INCREMENT (jmp_cond_mem)
GUM_DECLARE_OBSERVER_INCREMENT (jmp_cond_reg)
GUM_DECLARE_OBSERVER_INCREMENT (jmp_cond_jcxz)

GUM_DECLARE_OBSERVER_INCREMENT (jmp_cond_cc)
GUM_DECLARE_OBSERVER_INCREMENT (jmp_cond_cbz)
GUM_DECLARE_OBSERVER_INCREMENT (jmp_cond_cbnz)
GUM_DECLARE_OBSERVER_INCREMENT (jmp_cond_tbz)
GUM_DECLARE_OBSERVER_INCREMENT (jmp_cond_tbnz)

GUM_DECLARE_OBSERVER_INCREMENT (jmp_continuation)

GUM_DECLARE_OBSERVER_INCREMENT (sysenter_slow_path)

GUM_API void gum_stalker_observer_notify_backpatch (
    GumStalkerObserver * observer, const GumBackpatch * backpatch, gsize size);

GUM_API void gum_stalker_observer_switch_callback (
    GumStalkerObserver * observer, gpointer start_address,
    const cs_insn * from_insn, gpointer * target);

G_END_DECLS

#endif
