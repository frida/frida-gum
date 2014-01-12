/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
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

#include "gumcyclesampler.h"

#include "gumx86writer.h"
#include "gummemory.h"

typedef void (GUM_THUNK * ReadTimestampCounterFunc) (GumSample * sample);

struct _GumCycleSamplerPrivate
{
  ReadTimestampCounterFunc read_timestamp_counter;

  gpointer code;
};

static void gum_cycle_sampler_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_cycle_sampler_finalize (GObject * object);
static GumSample gum_cycle_sampler_sample (GumSampler * sampler);

G_DEFINE_TYPE_EXTENDED (GumCycleSampler,
                        gum_cycle_sampler,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SAMPLER,
                                               gum_cycle_sampler_iface_init));

static void
gum_cycle_sampler_class_init (GumCycleSamplerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_cycle_sampler_finalize;

  g_type_class_add_private (klass, sizeof (GumCycleSamplerPrivate));
}

static void
gum_cycle_sampler_iface_init (gpointer g_iface,
                              gpointer iface_data)
{
  GumSamplerIface * iface = (GumSamplerIface *) g_iface;

  (void) iface_data;

  iface->sample = gum_cycle_sampler_sample;
}

static void
gum_cycle_sampler_init (GumCycleSampler * self)
{
  GumCycleSamplerPrivate * priv;
  GumX86Writer cw;
  GumCpuReg first_arg_reg;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_CYCLE_SAMPLER,
      GumCycleSamplerPrivate);
  priv = self->priv;

  priv->code = gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_x86_writer_init (&cw, priv->code);
  gum_x86_writer_put_lfence (&cw);
  gum_x86_writer_put_rdtsc (&cw);
  first_arg_reg = gum_x86_writer_get_cpu_register_for_nth_argument (&cw, 0);
  gum_x86_writer_put_mov_reg_ptr_reg (&cw, first_arg_reg, GUM_REG_EAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, first_arg_reg, 4,
      GUM_REG_EDX);
  gum_x86_writer_put_ret (&cw);
  gum_x86_writer_free (&cw);

  priv->read_timestamp_counter =
      GUM_POINTER_TO_FUNCPTR (ReadTimestampCounterFunc, priv->code);
}

static void
gum_cycle_sampler_finalize (GObject * object)
{
  GumCycleSampler * self = GUM_CYCLE_SAMPLER (object);

  gum_free_pages (self->priv->code);

  G_OBJECT_CLASS (gum_cycle_sampler_parent_class)->finalize (object);
}

GumSampler *
gum_cycle_sampler_new (void)
{
  return GUM_SAMPLER_CAST (g_object_new (GUM_TYPE_CYCLE_SAMPLER, NULL));
}

static GumSample
gum_cycle_sampler_sample (GumSampler * sampler)
{
  GumCycleSampler * self = GUM_CYCLE_SAMPLER_CAST (sampler);
  GumSample result;

  self->priv->read_timestamp_counter (&result);

  return result;
}
