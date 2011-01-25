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

static void gum_x86_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_x86_backtracer_finalize (GObject * object);
static void gum_x86_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

static void update_code_ranges (GumX86Backtracer * self);
static gboolean is_valid_code_address (GumX86Backtracer * self, gsize address,
    guint size);

struct _GumX86BacktracerPrivate
{
  gboolean disposed;

  GPtrArray * code_ranges;
  gsize code_ranges_min;
  gsize code_ranges_max;
};

#define GUM_X86_BACKTRACER_GET_PRIVATE(o) ((o)->priv)

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

  self->priv->code_ranges = g_ptr_array_new ();

  update_code_ranges (self);
}

static void
gum_x86_backtracer_finalize (GObject * object)
{
  GumX86Backtracer * self = GUM_X86_BACKTRACER (object);
  GumX86BacktracerPrivate * priv =
      GUM_X86_BACKTRACER_GET_PRIVATE (self);

  g_ptr_array_free (priv->code_ranges, TRUE);

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
    start_address = GSIZE_TO_POINTER (cpu_context->esp);
  else
    g_assert_not_reached (); /* FIXME */

  return_addresses->len = 0;

  for (i = 0, p = start_address; i < G_N_ELEMENTS (return_addresses->items) &&
      p < start_address + 8192; p++)
  {
    gsize value;

    /*
    if (!is_valid_read_ptr (self, p, 4))
      break;
    */

    value = *p;

    if (value > 6 && is_valid_code_address (self, value - 6, 6))
    {
      guint8 * code_ptr = GSIZE_TO_POINTER (value);

      if (*(code_ptr - 5) == OPCODE_CALL_NEAR_RELATIVE ||
          *(code_ptr - 6) == OPCODE_CALL_NEAR_ABS_INDIRECT ||
          *(code_ptr - 3) == OPCODE_CALL_NEAR_ABS_INDIRECT ||
          *(code_ptr - 2) == OPCODE_CALL_NEAR_ABS_INDIRECT)
      {
        g_print ("value: 0x%08x\n", value);
        i++;
      }
    }
  }
}

typedef struct _MemoryRange MemoryRange;

struct _MemoryRange
{
  gsize start;
  gsize end;
};

static MemoryRange *
memory_range_new (gsize start,
                  gsize end)
{
  MemoryRange * range;

  range = g_new (MemoryRange, 1);
  range->start = start;
  range->end = end;

  return range;
}

static void
update_code_ranges (GumX86Backtracer * self)
{
  GumX86BacktracerPrivate * priv =
      GUM_X86_BACKTRACER_GET_PRIVATE (self);
  FILE * fp;
  gchar line[1024 + 1];
  MemoryRange * cur_range = NULL;
  MemoryRange * first_range, * last_range;

  g_ptr_array_set_size (priv->code_ranges, 0);

  fp = fopen ("/proc/self/maps", "r");
  g_assert (fp != NULL);

  while (fgets (line, sizeof (line), fp) != NULL)
  {
    gint n;
    gpointer start_ptr, end_ptr;
    gsize start_address, end_address;
    gchar protection[16];

    n = sscanf (line, "%p-%p %s ", &start_ptr, &end_ptr, protection);
    g_assert (n == 3);

    start_address = GPOINTER_TO_SIZE (start_ptr);
    end_address = GPOINTER_TO_SIZE (end_ptr);

    g_assert (strlen (protection) == 4);
    if (protection[0] == 'r' && protection[2] == 'x')
    {
      if (cur_range != NULL && start_address == cur_range->end)
      {
        cur_range->end = end_address;
      }
      else
      {
        cur_range = memory_range_new (start_address, end_address);
        g_ptr_array_add (priv->code_ranges, cur_range);
      }
    }
  }

  first_range = g_ptr_array_index (priv->code_ranges, 0);
  last_range = g_ptr_array_index (priv->code_ranges,
      priv->code_ranges->len - 1);

  priv->code_ranges_min = first_range->start;
  priv->code_ranges_max = last_range->end;

  fclose (fp);
}

static gboolean
is_valid_code_address (GumX86Backtracer * self,
                       gsize address,
                       guint size)
{
  GumX86BacktracerPrivate * priv =
      GUM_X86_BACKTRACER_GET_PRIVATE (self);
  guint i;

  if (address < priv->code_ranges_min)
    return FALSE;
  else if (address + size > priv->code_ranges_max)
    return FALSE;

  for (i = 0; i < priv->code_ranges->len; i++)
  {
    MemoryRange * range = g_ptr_array_index (priv->code_ranges, i);

    if (address >= range->start && address + size <= range->end)
      return TRUE;
  }

  return FALSE;
}

