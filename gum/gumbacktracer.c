/*
 * Copyright (C) 2008-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumbacktracer.h"

#ifdef G_OS_WIN32
# include "backend-dbghelp/gumdbghelpbacktracer.h"
# include "arch-x86/gumx86backtracer.h"
#elif defined (HAVE_DARWIN)
# include "backend-darwin/gumdarwinbacktracer.h"
#elif defined (HAVE_LIBUNWIND)
# include "backend-libunwind/gumunwbacktracer.h"
#endif

#if defined (HAVE_I386)
# include "arch-x86/gumx86backtracer.h"
#elif defined (HAVE_ARM)
# include "arch-arm/gumarmbacktracer.h"
#elif defined (HAVE_ARM64)
# include "arch-arm64/gumarm64backtracer.h"
#elif defined (HAVE_MIPS)
# include "arch-mips/gummipsbacktracer.h"
#endif

G_DEFINE_INTERFACE (GumBacktracer, gum_backtracer, G_TYPE_OBJECT)

static void
gum_backtracer_default_init (GumBacktracerInterface * iface)
{
}

GumBacktracer *
gum_backtracer_make_accurate (void)
{
#if defined (G_OS_WIN32)
  GumDbghelpImpl * dbghelp;

  dbghelp = gum_dbghelp_impl_try_obtain ();
  if (dbghelp == NULL)
    return NULL;
  return gum_dbghelp_backtracer_new (dbghelp);
#elif defined (HAVE_DARWIN)
  return gum_darwin_backtracer_new ();
#elif defined (HAVE_LIBUNWIND)
  return gum_unw_backtracer_new ();
#else
  return NULL;
#endif
}

GumBacktracer *
gum_backtracer_make_fuzzy (void)
{
#if defined (HAVE_I386)
  return gum_x86_backtracer_new ();
#elif defined (HAVE_ARM)
  return gum_arm_backtracer_new ();
#elif defined (HAVE_ARM64)
  return gum_arm64_backtracer_new ();
#elif defined (HAVE_MIPS)
  return gum_mips_backtracer_new ();
#else
  return NULL;
#endif
}

void
gum_backtracer_generate (GumBacktracer * self,
                         const GumCpuContext * cpu_context,
                         GumReturnAddressArray * return_addresses)
{
  GumBacktracerInterface * iface = GUM_BACKTRACER_GET_IFACE (self);

  g_assert (iface->generate != NULL);

  iface->generate (self, cpu_context, return_addresses);
}
