/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsampler.h"

GType
gum_sampler_get_type (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GType gtype;

    gtype = g_type_register_static_simple (G_TYPE_INTERFACE, "GumSampler",
        sizeof (GumSamplerIface), NULL, 0, NULL, 0);
    g_type_interface_add_prerequisite (gtype, G_TYPE_OBJECT);

    g_once_init_leave (&gonce_value, gtype);
  }

  return (GType) gonce_value;
}

GumSample
gum_sampler_sample (GumSampler * self)
{
  GumSamplerIface * iface = GUM_SAMPLER_GET_INTERFACE (self);

  g_assert (iface->sample != NULL);

  return iface->sample (self);
}
