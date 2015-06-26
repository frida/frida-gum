/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumarm64backtracer.h"

#include "guminterceptor.h"
#include "gummemorymap.h"

struct _GumArm64BacktracerPrivate
{
  GumMemoryMap * code;
  GumMemoryMap * writable;
};

static void gum_arm64_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_arm64_backtracer_dispose (GObject * object);
static void gum_arm64_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

G_DEFINE_TYPE_EXTENDED (GumArm64Backtracer,
                        gum_arm64_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_arm64_backtracer_iface_init));

static void
gum_arm64_backtracer_class_init (GumArm64BacktracerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumArm64BacktracerPrivate));

  object_class->dispose = gum_arm64_backtracer_dispose;
}

static void
gum_arm64_backtracer_iface_init (gpointer g_iface,
                                 gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  iface->generate = gum_arm64_backtracer_generate;
}

static void
gum_arm64_backtracer_init (GumArm64Backtracer * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_ARM64_BACKTRACER,
      GumArm64BacktracerPrivate);

  self->priv->code = gum_memory_map_new (GUM_PAGE_EXECUTE);
  self->priv->writable = gum_memory_map_new (GUM_PAGE_WRITE);
}

static void
gum_arm64_backtracer_dispose (GObject * object)
{
  GumArm64Backtracer * self = GUM_ARM64_BACKTRACER (object);
  GumArm64BacktracerPrivate * priv = self->priv;

  if (priv->code != NULL)
  {
    g_object_unref (priv->code);
    priv->code = NULL;
  }

  if (priv->writable != NULL)
  {
    g_object_unref (priv->writable);
    priv->writable = NULL;
  }

  G_OBJECT_CLASS (gum_arm64_backtracer_parent_class)->dispose (object);
}

GumBacktracer *
gum_arm64_backtracer_new (void)
{
  return g_object_new (GUM_TYPE_ARM64_BACKTRACER, NULL);
}

static void
gum_arm64_backtracer_generate (GumBacktracer * backtracer,
                               const GumCpuContext * cpu_context,
                               GumReturnAddressArray * return_addresses)
{
  GumArm64Backtracer * self = GUM_ARM64_BACKTRACER_CAST (backtracer);
  GumArm64BacktracerPrivate * priv = self->priv;
  GumInvocationStack * invocation_stack;
  gsize * start_address;
  guint skips_pending, i;
  gsize * p;

  invocation_stack = gum_interceptor_get_current_stack ();

  if (cpu_context != NULL)
  {
    start_address = GSIZE_TO_POINTER (cpu_context->sp);
    skips_pending = 0;
  }
  else
  {
    asm ("\tmov %0, sp" : "=r" (start_address));
    skips_pending = 1;
  }

  for (i = 0, p = start_address; p < start_address + 2048; p++)
  {
    gboolean valid = FALSE;
    gsize value;
    GumMemoryRange vr;

    if ((GPOINTER_TO_SIZE (p) & (4096 - 1)) == 0)
    {
      GumMemoryRange next_range;
      next_range.base_address = GUM_ADDRESS (p);
      next_range.size = 4096;
      if (!gum_memory_map_contains (priv->writable, &next_range))
        break;
    }

    value = *p;
    vr.base_address = value - 4;
    vr.size = 4;

    if (value > 4096 + 4 &&
        (value & 0x3) == 0 &&
        gum_memory_map_contains (priv->code, &vr))
    {
      gsize translated_value;

      translated_value = GPOINTER_TO_SIZE (gum_invocation_stack_translate (
          invocation_stack, GSIZE_TO_POINTER (value)));
      if (translated_value != value)
      {
        value = translated_value;
        valid = TRUE;
      }
      else
      {
        const guint32 insn = *((guint32 *) GSIZE_TO_POINTER (value - 4));
        if ((insn & 0xfc000000) == 0x94000000)
        {
          /* BL <imm26> */
          valid = TRUE;
        }
        else if ((insn & 0xfffffc1f) == 0xd63f0000)
        {
          /* BLR <reg> */
          valid = TRUE;
        }
      }
    }

    if (valid)
    {
      if (skips_pending == 0)
      {
        return_addresses->items[i++] = GSIZE_TO_POINTER (value);
        if (i == G_N_ELEMENTS (return_addresses->items))
          break;
      }
      else
      {
        skips_pending--;
      }
    }
  }

  return_addresses->len = i;
}

