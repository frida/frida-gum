/*
 * Copyright (C) 2012 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumnsbacktracer.h"

#include "gum-init.h"

#include <dlfcn.h>
#include <objc/runtime.h>
#import <Foundation/Foundation.h>

static gboolean gum_ns_backtracer_try_init (void);
static void gum_ns_backtracer_do_deinit (void);

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

static void * gum_foundation;
static Class gum_ns_autorelease_pool;
static Class gum_ns_thread;

static gboolean
gum_ns_backtracer_try_init (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    void * cf;

    cf = dlopen ("/System/Library/Frameworks/"
        "CoreFoundation.framework/CoreFoundation",
        RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD);
    if (cf != NULL)
    {
      dlclose (cf);

      gum_foundation = dlopen ("/System/Library/Frameworks/"
          "Foundation.framework/Foundation",
          RTLD_LAZY | RTLD_GLOBAL);
      if (gum_foundation != NULL)
      {
        gum_ns_autorelease_pool = objc_getClass ("NSAutoreleasePool");
        g_assert (gum_ns_autorelease_pool != nil);
        gum_ns_thread = objc_getClass ("NSThread");
        g_assert (gum_ns_thread != nil);

        _gum_register_destructor (gum_ns_backtracer_do_deinit);
      }
    }

    g_once_init_leave (&gonce_value, 1 + (gum_foundation != NULL));
  }

  return gonce_value - 1;
}

static void
gum_ns_backtracer_do_deinit (void)
{
  gum_ns_thread = nil;
  gum_ns_autorelease_pool = nil;

  dlclose (gum_foundation);
  gum_foundation = NULL;
}

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
  gboolean success;

  success = gum_ns_backtracer_try_init ();
  g_assert (success);
}

gboolean
gum_ns_backtracer_is_available (void)
{
  return gum_ns_backtracer_try_init ();
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
  NSAutoreleasePool * pool;
  NSArray * ret_addrs;
  gsize i;

  pool = [[gum_ns_autorelease_pool alloc] init];

  ret_addrs = [gum_ns_thread callStackReturnAddresses];
  for (i = 0;
      (i + 1 < [ret_addrs count]) &&
          (i < G_N_ELEMENTS (return_addresses->items));
      i++)
  {
    gsize item = [[ret_addrs objectAtIndex:i + 1] unsignedLongLongValue];
    return_addresses->items[i] = GSIZE_TO_POINTER (item);
  }

  return_addresses->len = i;
  [pool release];
}

