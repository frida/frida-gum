/*
 * Copyright (C) 2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumarmbacktracer.h"

#include "guminterceptor.h"
#include "gummemorymap.h"

struct _GumArmBacktracerPrivate
{
  GumMemoryMap * code;
  GumMemoryMap * writable;
};

static void gum_arm_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_arm_backtracer_dispose (GObject * object);
static void gum_arm_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

G_DEFINE_TYPE_EXTENDED (GumArmBacktracer,
                        gum_arm_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_arm_backtracer_iface_init));

static void
gum_arm_backtracer_class_init (GumArmBacktracerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumArmBacktracerPrivate));

  object_class->dispose = gum_arm_backtracer_dispose;
}

static void
gum_arm_backtracer_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  iface->generate = gum_arm_backtracer_generate;
}

static void
gum_arm_backtracer_init (GumArmBacktracer * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_ARM_BACKTRACER,
      GumArmBacktracerPrivate);

  self->priv->code = gum_memory_map_new (GUM_PAGE_EXECUTE);
  self->priv->writable = gum_memory_map_new (GUM_PAGE_WRITE);
}

static void
gum_arm_backtracer_dispose (GObject * object)
{
  GumArmBacktracer * self = GUM_ARM_BACKTRACER (object);
  GumArmBacktracerPrivate * priv = self->priv;

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

  G_OBJECT_CLASS (gum_arm_backtracer_parent_class)->dispose (object);
}

GumBacktracer *
gum_arm_backtracer_new (void)
{
  return g_object_new (GUM_TYPE_ARM_BACKTRACER, NULL);
}

static void
gum_arm_backtracer_generate (GumBacktracer * backtracer,
                             const GumCpuContext * cpu_context,
                             GumReturnAddressArray * return_addresses)
{
  GumArmBacktracer * self = GUM_ARM_BACKTRACER_CAST (backtracer);
  GumArmBacktracerPrivate * priv = self->priv;
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

    if (value > 4096 + 4 && gum_memory_map_contains (priv->code, &vr))
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
        if (value % 4 == 0)
        {
          const guint32 insn = *((guint32 *) GSIZE_TO_POINTER (value - 4));
          if ((insn & 0xf000000) == 0xb000000)
          {
            /* BL <imm24> */
            valid = TRUE;
          }
          else if ((insn & 0xfe000000) == 0xfa000000)
          {
            /* BLX <imm24> */
            valid = TRUE;
          }
          else if ((insn & 0xff000f0) == 0x1200030)
          {
            /* BLX Rx */
            valid = TRUE;
          }
        }
        else if ((value & 1) != 0)
        {
          const guint16 * insns_before = GSIZE_TO_POINTER (value - 1 - 2 - 2);
          if ((insns_before[0] & 0xf800) == 0xf000 &&
              (insns_before[1] & 0xe800) == 0xe800)
          {
            /* BL/BLX <imm11> */
            value--;
            valid = TRUE;
          }
          else if ((insns_before[1] & 0xff80) == 0x4780)
          {
            /* BLX Rx */
            value--;
            valid = TRUE;
          }
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

