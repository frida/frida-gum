/*
 * Copyright (C) 2008-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumx86backtracer.h"

#include "gumsymbolutil.h"

typedef struct _GumCodeRange GumCodeRange;
typedef struct _GumUpdateCodeRangesCtx GumUpdateCodeRangesCtx;

struct _GumX86BacktracerPrivate
{
  gboolean disposed;

  GArray * code_ranges;
  gsize code_ranges_min;
  gsize code_ranges_max;
};

struct _GumCodeRange
{
  gsize start;
  gsize end;
};

struct _GumUpdateCodeRangesCtx
{
  GumX86Backtracer * self;
  gint prev_range_index;
};

static void gum_x86_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_x86_backtracer_finalize (GObject * object);
static void gum_x86_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

static void gum_x86_backtracer_update_code_ranges (GumX86Backtracer * self);
static gboolean gum_x86_backtracer_add_code_range (const GumMemoryRange * range,
    GumPageProtection prot, gpointer user_data);
static gboolean gum_is_valid_code_address (GumX86Backtracer * self,
    gsize address, guint size);

G_DEFINE_TYPE_EXTENDED (GumX86Backtracer,
                        gum_x86_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_x86_backtracer_iface_init));

static void
gum_x86_backtracer_class_init (GumX86BacktracerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumX86BacktracerPrivate));

  object_class->finalize = gum_x86_backtracer_finalize;
}

static void
gum_x86_backtracer_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  iface->generate = gum_x86_backtracer_generate;
}

static void
gum_x86_backtracer_init (GumX86Backtracer * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_X86_BACKTRACER,
      GumX86BacktracerPrivate);

  self->priv->code_ranges = g_array_new (FALSE, FALSE, sizeof (GumCodeRange));

  gum_x86_backtracer_update_code_ranges (self);
}

static void
gum_x86_backtracer_finalize (GObject * object)
{
  GumX86Backtracer * self = GUM_X86_BACKTRACER (object);

  g_array_free (self->priv->code_ranges, TRUE);

  G_OBJECT_CLASS (gum_x86_backtracer_parent_class)->finalize (object);
}

GumBacktracer *
gum_x86_backtracer_new (void)
{
  return g_object_new (GUM_TYPE_X86_BACKTRACER, NULL);
}

#define OPCODE_CALL_NEAR_RELATIVE     0xE8
#define OPCODE_CALL_NEAR_ABS_INDIRECT 0xFF

static void
gum_x86_backtracer_generate (GumBacktracer * backtracer,
                             const GumCpuContext * cpu_context,
                             GumReturnAddressArray * return_addresses)
{
  GumX86Backtracer * self = GUM_X86_BACKTRACER_CAST (backtracer);
  gsize * start_address;
  guint i;
  gsize * p;

  if (cpu_context != NULL)
    start_address = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XSP (cpu_context));
  else
    start_address = (gsize *) &return_addresses + 1;

  for (i = 0, p = start_address; p < start_address + 8192; p++)
  {
    gsize value = *p;

    if (value > 6 && gum_is_valid_code_address (self, value - 6, 6))
    {
      guint8 * code_ptr = GSIZE_TO_POINTER (value);

      if (*(code_ptr - 5) == OPCODE_CALL_NEAR_RELATIVE ||
          *(code_ptr - 6) == OPCODE_CALL_NEAR_ABS_INDIRECT ||
          *(code_ptr - 3) == OPCODE_CALL_NEAR_ABS_INDIRECT ||
          *(code_ptr - 2) == OPCODE_CALL_NEAR_ABS_INDIRECT)
      {
        return_addresses->items[i++] = GSIZE_TO_POINTER (value);
        if (i == G_N_ELEMENTS (return_addresses->items))
          break;
      }
    }
  }

  return_addresses->len = i;
}

static void
gum_x86_backtracer_update_code_ranges (GumX86Backtracer * self)
{
  GumX86BacktracerPrivate * priv = self->priv;
  GumUpdateCodeRangesCtx ctx;
  GumCodeRange * first_range, * last_range;

  ctx.self = self;
  ctx.prev_range_index = -1;

  g_array_set_size (priv->code_ranges, 0);

  gum_process_enumerate_ranges (GUM_PAGE_EXECUTE,
      gum_x86_backtracer_add_code_range, &ctx);

  first_range = &g_array_index (priv->code_ranges, GumCodeRange, 0);
  last_range = &g_array_index (priv->code_ranges, GumCodeRange,
      priv->code_ranges->len - 1);

  priv->code_ranges_min = first_range->start;
  priv->code_ranges_max = last_range->end;
}

static gboolean
gum_x86_backtracer_add_code_range (const GumMemoryRange * range,
                                   GumPageProtection prot,
                                   gpointer user_data)
{
  GumUpdateCodeRangesCtx * ctx = (GumUpdateCodeRangesCtx *) user_data;
  GArray * ranges = ctx->self->priv->code_ranges;
  GumCodeRange cur_range, * prev_range;

  cur_range.start = GPOINTER_TO_SIZE (range->base_address);
  cur_range.end = cur_range.start + range->size;

  if (ctx->prev_range_index >= 0)
    prev_range = &g_array_index (ranges, GumCodeRange, ctx->prev_range_index);
  else
    prev_range = NULL;

  if (prev_range != NULL && cur_range.start == prev_range->end)
    prev_range->end = cur_range.end;
  else
    g_array_append_val (ranges, cur_range);

  return TRUE;
}

static gboolean
gum_is_valid_code_address (GumX86Backtracer * self,
                           gsize address,
                           guint size)
{
  GumX86BacktracerPrivate * priv = self->priv;
  guint i;

  if (address < priv->code_ranges_min)
    return FALSE;
  else if (address + size > priv->code_ranges_max)
    return FALSE;

  for (i = 0; i < priv->code_ranges->len; i++)
  {
    GumCodeRange * range = &g_array_index (priv->code_ranges, GumCodeRange, i);

    if (address >= range->start && address + size <= range->end)
      return TRUE;
  }

  return FALSE;
}
