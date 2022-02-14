/*
 * Copyright (C) 2017-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumstalker.h"

struct _GumDefaultStalkerTransformer
{
  GObject parent;
};

struct _GumCallbackStalkerTransformer
{
  GObject parent;

  GumStalkerTransformerCallback callback;
  gpointer data;
  GDestroyNotify data_destroy;
};

static void gum_default_stalker_transformer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_default_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer, GumStalkerIterator * iterator,
    GumStalkerOutput * output);

static void gum_callback_stalker_transformer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_callback_stalker_transformer_finalize (GObject * object);
static void gum_callback_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer, GumStalkerIterator * iterator,
    GumStalkerOutput * output);

static void gum_stalker_observer_default_init (
    GumStalkerObserverInterface * iface);

G_DEFINE_INTERFACE (GumStalkerTransformer, gum_stalker_transformer,
                    G_TYPE_OBJECT)

G_DEFINE_TYPE_EXTENDED (GumDefaultStalkerTransformer,
                        gum_default_stalker_transformer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_STALKER_TRANSFORMER,
                            gum_default_stalker_transformer_iface_init))

G_DEFINE_TYPE_EXTENDED (GumCallbackStalkerTransformer,
                        gum_callback_stalker_transformer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_STALKER_TRANSFORMER,
                            gum_callback_stalker_transformer_iface_init))

G_DEFINE_INTERFACE (GumStalkerObserver, gum_stalker_observer, G_TYPE_OBJECT)

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

static void
gum_stalker_transformer_default_init (GumStalkerTransformerInterface * iface)
{
}

/**
 * gum_stalker_transformer_make_default:
 *
 * Creates a default #GumStalkerTransformer that recompiles code without any
 * custom transformations.
 *
 * Returns: (transfer full): a newly created #GumStalkerTransformer
 */
GumStalkerTransformer *
gum_stalker_transformer_make_default (void)
{
  return g_object_new (GUM_TYPE_DEFAULT_STALKER_TRANSFORMER, NULL);
}

/**
 * gum_stalker_transformer_make_from_callback:
 * @callback: (not nullable): function called to transform each basic block
 * @data: (nullable): data to pass to @callback
 * @data_destroy: (nullable) (destroy data): function to destroy @data
 *
 * Creates a #GumStalkerTransformer that recompiles code by letting @callback
 * apply custom transformations for any given basic block.
 *
 * Returns: (transfer full): a newly created #GumStalkerTransformer
 */
GumStalkerTransformer *
gum_stalker_transformer_make_from_callback (
    GumStalkerTransformerCallback callback,
    gpointer data,
    GDestroyNotify data_destroy)
{
  GumCallbackStalkerTransformer * transformer;

  transformer = g_object_new (GUM_TYPE_CALLBACK_STALKER_TRANSFORMER, NULL);
  transformer->callback = callback;
  transformer->data = data;
  transformer->data_destroy = data_destroy;

  return GUM_STALKER_TRANSFORMER (transformer);
}

void
gum_stalker_transformer_transform_block (GumStalkerTransformer * self,
                                         GumStalkerIterator * iterator,
                                         GumStalkerOutput * output)
{
  GumStalkerTransformerInterface * iface =
      GUM_STALKER_TRANSFORMER_GET_IFACE (self);

  g_assert (iface->transform_block != NULL);

  iface->transform_block (self, iterator, output);
}

static void
gum_default_stalker_transformer_class_init (
    GumDefaultStalkerTransformerClass * klass)
{
}

static void
gum_default_stalker_transformer_iface_init (gpointer g_iface,
                                            gpointer iface_data)
{
  GumStalkerTransformerInterface * iface = g_iface;

  iface->transform_block = gum_default_stalker_transformer_transform_block;
}

static void
gum_default_stalker_transformer_init (GumDefaultStalkerTransformer * self)
{
}

static void
gum_default_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerOutput * output)
{
  while (gum_stalker_iterator_next (iterator, NULL))
  {
    gum_stalker_iterator_keep (iterator);
  }
}

static void
gum_callback_stalker_transformer_class_init (
    GumCallbackStalkerTransformerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_callback_stalker_transformer_finalize;
}

static void
gum_callback_stalker_transformer_iface_init (gpointer g_iface,
                                             gpointer iface_data)
{
  GumStalkerTransformerInterface * iface = g_iface;

  iface->transform_block = gum_callback_stalker_transformer_transform_block;
}

static void
gum_callback_stalker_transformer_init (GumCallbackStalkerTransformer * self)
{
}

static void
gum_callback_stalker_transformer_finalize (GObject * object)
{
  GumCallbackStalkerTransformer * self =
      GUM_CALLBACK_STALKER_TRANSFORMER (object);

  if (self->data_destroy != NULL)
    self->data_destroy (self->data);

  G_OBJECT_CLASS (gum_callback_stalker_transformer_parent_class)->finalize (
      object);
}

static void
gum_callback_stalker_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerOutput * output)
{
  GumCallbackStalkerTransformer * self =
      (GumCallbackStalkerTransformer *) transformer;

  self->callback (iterator, output, self->data);
}

/**
 * gum_stalker_iterator_next:
 * @self: a #GumStalkerIterator
 * @insn: (type gpointer*) (out) (transfer none) (optional): return location for
 *        a pointer to the next instruction, or %NULL
 *
 * Advances the iterator to the next instruction.
 *
 * Returns: %TRUE if there is a next instruction, else %FALSE
 */

static void
gum_stalker_observer_default_init (GumStalkerObserverInterface * iface)
{
}

#define GUM_DEFINE_OBSERVER_INCREMENT(name) \
    void \
    gum_stalker_observer_increment_##name (GumStalkerObserver * observer) \
    { \
      GumStalkerObserverInterface * iface; \
      \
      iface = GUM_STALKER_OBSERVER_GET_IFACE (observer); \
      g_assert (iface != NULL); \
      \
      if (iface->increment_##name == NULL) \
        return; \
      \
      iface->increment_##name (observer); \
    }

GUM_DEFINE_OBSERVER_INCREMENT (total)

GUM_DEFINE_OBSERVER_INCREMENT (call_imm)
GUM_DEFINE_OBSERVER_INCREMENT (call_reg)

GUM_DEFINE_OBSERVER_INCREMENT (call_mem)

GUM_DEFINE_OBSERVER_INCREMENT (excluded_call_reg)

GUM_DEFINE_OBSERVER_INCREMENT (ret_slow_path)

GUM_DEFINE_OBSERVER_INCREMENT (ret)

GUM_DEFINE_OBSERVER_INCREMENT (post_call_invoke)
GUM_DEFINE_OBSERVER_INCREMENT (excluded_call_imm)

GUM_DEFINE_OBSERVER_INCREMENT (jmp_imm)
GUM_DEFINE_OBSERVER_INCREMENT (jmp_reg)

GUM_DEFINE_OBSERVER_INCREMENT (jmp_mem)
GUM_DEFINE_OBSERVER_INCREMENT (jmp_cond_imm)
GUM_DEFINE_OBSERVER_INCREMENT (jmp_cond_mem)
GUM_DEFINE_OBSERVER_INCREMENT (jmp_cond_reg)
GUM_DEFINE_OBSERVER_INCREMENT (jmp_cond_jcxz)

GUM_DEFINE_OBSERVER_INCREMENT (jmp_cond_cc)
GUM_DEFINE_OBSERVER_INCREMENT (jmp_cond_cbz)
GUM_DEFINE_OBSERVER_INCREMENT (jmp_cond_cbnz)
GUM_DEFINE_OBSERVER_INCREMENT (jmp_cond_tbz)
GUM_DEFINE_OBSERVER_INCREMENT (jmp_cond_tbnz)

GUM_DEFINE_OBSERVER_INCREMENT (jmp_continuation)

GUM_DEFINE_OBSERVER_INCREMENT (sysenter_slow_path)

void
gum_stalker_observer_notify_backpatch (GumStalkerObserver * observer,
                                       const GumBackpatch * backpatch,
                                       gsize size)
{
  GumStalkerObserverInterface * iface;

  iface = GUM_STALKER_OBSERVER_GET_IFACE (observer);
  g_assert (iface != NULL);

  if (iface->notify_backpatch == NULL)
    return;

  iface->notify_backpatch (observer, backpatch, size);
}

void
gum_stalker_observer_switch_callback (GumStalkerObserver * observer,
                                      gpointer from_address,
                                      gpointer start_address,
                                      const cs_insn * from_insn,
                                      gpointer * target)
{
  GumStalkerObserverInterface * iface;

  iface = GUM_STALKER_OBSERVER_GET_IFACE (observer);
  g_assert (iface != NULL);

  if (iface->switch_callback == NULL)
    return;

  iface->switch_callback (observer, from_address, start_address, from_insn,
      target);
}

#endif
