/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry-priv.h"

#include "gummodule-darwin.h"

#include <dlfcn.h>
#include <string.h>
#include <mach-o/dyld.h>

static void gum_module_registry_on_image_added (const struct mach_header * mh,
    intptr_t vmaddr_slide);
static void gum_module_registry_on_image_removed (const struct mach_header * mh,
    intptr_t vmaddr_slide);

static gsize gum_detect_macho_size (const struct mach_header * mh);

static GumModuleRegistry * _the_registry;

void
_gum_module_registry_activate (GumModuleRegistry * self)
{
  _the_registry = self;

  _dyld_register_func_for_add_image (gum_module_registry_on_image_added);
  _dyld_register_func_for_remove_image (gum_module_registry_on_image_removed);
}

static void
gum_module_registry_on_image_added (const struct mach_header * mh,
                                    intptr_t vmaddr_slide)
{
  Dl_info info;
  GumMemoryRange range;

  dladdr (mh, &info);

  range.base_address = GUM_ADDRESS (mh);
  range.size = gum_detect_macho_size (mh);

  _gum_module_registry_register (_the_registry,
      GUM_MODULE (_gum_native_module_make (info.dli_fname, &range, NULL)));
}

static void
gum_module_registry_on_image_removed (const struct mach_header * mh,
                                      intptr_t vmaddr_slide)
{
  _gum_module_registry_unregister (_the_registry, GUM_ADDRESS (mh));
}

static gsize
gum_detect_macho_size (const struct mach_header * mh)
{
  gconstpointer first_command, p;
  guint i;

#if GLIB_SIZEOF_VOID_P == 8
  first_command = (const guint8 *) mh + sizeof (struct mach_header_64);
#else
  first_command = (const guint8 *) mh + sizeof (struct mach_header);
#endif

  p = first_command;
  for (i = 0; i != mh->ncmds; i++)
  {
    const struct load_command * lc = p;

    if (lc->cmd == LC_SEGMENT)
    {
      const struct segment_command * sc = p;
      if (strcmp (sc->segname, "__TEXT") == 0)
        return sc->vmsize;
    }
    else if (lc->cmd == LC_SEGMENT_64)
    {
      const struct segment_command_64 * sc = p;
      if (strcmp (sc->segname, "__TEXT") == 0)
        return sc->vmsize;
    }

    p += lc->cmdsize;
  }

  g_assert_not_reached ();
}
