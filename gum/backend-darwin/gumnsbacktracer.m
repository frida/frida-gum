/*
 * Copyright (C) 2012 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumnsbacktracer.h"

#import <Foundation/Foundation.h>

static void gum_ns_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_ns_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

G_DEFINE_TYPE_EXTENDED (GumNsBacktracer,
                        gum_ns_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                                               gum_ns_backtracer_iface_init));

static void
gum_ns_backtracer_class_init (GumNsBacktracerClass * klass)
{
}

static void
gum_ns_backtracer_iface_init (gpointer g_iface,
                              gpointer iface_data)
{
  GumBacktracerIface * iface = (GumBacktracerIface *) g_iface;

  iface->generate = gum_ns_backtracer_generate;
}

static void
gum_ns_backtracer_init (GumNsBacktracer * self)
{
}

GumBacktracer *
gum_ns_backtracer_new (void)
{
  return g_object_new (GUM_TYPE_NS_BACKTRACER, NULL);
}

static void
gum_ns_backtracer_generate (GumBacktracer * backtracer,
                            const GumCpuContext * cpu_context,
                            GumReturnAddressArray * return_addresses)
{
  gsize i;

  NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];

  NSArray * ret_addrs = [NSThread callStackReturnAddresses];
  for (i = 0;
      ((i+1) < [ret_addrs count]) && (i < G_N_ELEMENTS (return_addresses->items));
      i++)
  {
    gsize item = [[ret_addrs objectAtIndex:(i+1)] unsignedLongLongValue];
    return_addresses->items[i] = GSIZE_TO_POINTER (item);
  }

  return_addresses->len = i;
  [pool release];
}

