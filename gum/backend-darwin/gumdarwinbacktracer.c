/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdarwinbacktracer.h"

#include "guminterceptor.h"

#define GUM_FP_LINK_OFFSET 1
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
# define GUM_FP_IS_ALIGNED(F) ((GPOINTER_TO_SIZE (F) & 0xf) == 8)
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# define GUM_FP_IS_ALIGNED(F) ((GPOINTER_TO_SIZE (F) & 0xf) == 0)
#else
# define GUM_FP_IS_ALIGNED(F) ((GPOINTER_TO_SIZE (F) & 0x1) == 0)
#endif

static void gum_darwin_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_darwin_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

G_DEFINE_TYPE_EXTENDED (GumDarwinBacktracer,
                        gum_darwin_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_darwin_backtracer_iface_init));

static void
gum_darwin_backtracer_class_init (GumDarwinBacktracerClass * klass)
{
}

static void
gum_darwin_backtracer_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  iface->generate = gum_darwin_backtracer_generate;
}

static void
gum_darwin_backtracer_init (GumDarwinBacktracer * self)
{
}

GumBacktracer *
gum_darwin_backtracer_new (void)
{
  return g_object_new (GUM_TYPE_DARWIN_BACKTRACER, NULL);
}

static void
gum_darwin_backtracer_generate (GumBacktracer * backtracer,
                                const GumCpuContext * cpu_context,
                                GumReturnAddressArray * return_addresses)
{
  pthread_t thread;
  gpointer stack_top, stack_bottom;
  gpointer * cur;
  guint start_index, i;
  GumInvocationStack * invocation_stack;

  thread = pthread_self ();
  stack_top = pthread_get_stackaddr_np (thread);
  stack_bottom = stack_top - pthread_get_stacksize_np (thread);
  stack_top -= (GUM_FP_LINK_OFFSET + 1) * sizeof (gpointer);

  if (cpu_context != NULL)
  {
#if defined (HAVE_I386)
    cur = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XBP (cpu_context));

    return_addresses->items[0] =
        GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));
#elif defined (HAVE_ARM)
    cur = GSIZE_TO_POINTER (cpu_context->r[7]);

    return_addresses->items[0] = GSIZE_TO_POINTER (cpu_context->pc);
#elif defined (HAVE_ARM64)
    cur = GSIZE_TO_POINTER (cpu_context->fp);

    return_addresses->items[0] = GSIZE_TO_POINTER (cpu_context->pc);
#else
# error Unsupported architecture
#endif
    start_index = 1;
  }
  else
  {
    cur = __builtin_frame_address (0);

    start_index = 0;
  }

  for (i = start_index;
      i < G_N_ELEMENTS (return_addresses->items) &&
      cur >= (gpointer *) stack_bottom &&
      cur <= (gpointer *) stack_top &&
      GUM_FP_IS_ALIGNED (cur);
      i++)
  {
    gpointer * next;

    return_addresses->items[i] = *(cur + GUM_FP_LINK_OFFSET);

    next = *cur;
    if (next <= cur)
      break;
    cur = next;
  }
  return_addresses->len = i;

  invocation_stack = gum_interceptor_get_current_stack ();
  for (i = 0; i != return_addresses->len; i++)
  {
    return_addresses->items[i] = gum_invocation_stack_translate (
        invocation_stack, return_addresses->items[i]);
  }
}

