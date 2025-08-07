/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry-priv.h"

#include "gum/gumdarwin.h"
#include "gumdarwin-priv.h"
#include "gummodule-darwin.h"

#include <dlfcn.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>

typedef struct _GumDyldNotifierContext GumDyldNotifierContext;
typedef void (* DyldImageNotifier) (enum dyld_image_mode mode,
    guint32 info_count, const struct dyld_image_info info[]);

struct _GumDyldNotifierContext
{
  gpointer * slot;
  DyldImageNotifier original;
};

static void gum_module_registry_on_image_added (const struct mach_header * mh,
    intptr_t vmaddr_slide);
static void gum_module_registry_on_image_removed (const struct mach_header * mh,
    intptr_t vmaddr_slide);
static void gum_lldb_image_notifier (enum dyld_image_mode mode,
    guint32 info_count, const struct dyld_image_info info[]);

static void gum_add_image (const struct mach_header * mh, const gchar * name);
static void gum_remove_image (const struct mach_header * mh);

static gsize gum_detect_macho_size (const struct mach_header * mh);

static GumModuleRegistry * gum_registry;
static GumDarwinModuleResolver * gum_resolver;
static GumDyldNotifierContext * gum_dyld_notifier_context;

void
_gum_module_registry_activate (GumModuleRegistry * self)
{
  GumDarwinAllImageInfos infos = { 0, };

  gum_registry = self;
  gum_resolver = gum_darwin_module_resolver_new_with_loader (mach_task_self (),
      (GumDarwinModuleResolverLoadFunc) _gum_module_registry_get_modules,
      gum_registry, NULL, NULL);

  if (!gum_darwin_query_all_image_infos (mach_task_self (), &infos))
    return;

  if (gum_process_get_teardown_requirement () == GUM_TEARDOWN_REQUIREMENT_FULL)
  {
    gpointer * slot;
    uint32_t count, i;

    g_assert (infos.dyld_all_image_infos_address != 0);

    if (infos.format == TASK_DYLD_ALL_IMAGE_INFO_64)
    {
      slot = gum_strip_code_pointer (
          GSIZE_TO_POINTER (infos.dyld_all_image_infos_address +
              offsetof (DyldAllImageInfos64, notification)));
    }
    else
    {
      slot = GSIZE_TO_POINTER (infos.dyld_all_image_infos_address +
          offsetof (DyldAllImageInfos32, notification));
    }

    gum_dyld_notifier_context = g_slice_new (GumDyldNotifierContext);

    gum_dyld_notifier_context->slot = slot;
    gum_dyld_notifier_context->original = *slot;

    *slot = gum_sign_code_pointer (
        gum_strip_code_pointer (gum_lldb_image_notifier));

    do
    {
      _gum_module_registry_reset (gum_registry);

      count = _dyld_image_count ();
      for (i = 0; i != count; i++)
        gum_add_image (_dyld_get_image_header (i), _dyld_get_image_name (i));
    }
    while (_dyld_image_count () != count);
  }
  else
  {
    _dyld_register_func_for_add_image (gum_module_registry_on_image_added);
    _dyld_register_func_for_remove_image (gum_module_registry_on_image_removed);
  }

  gum_add_image (GSIZE_TO_POINTER (infos.dyld_image_load_address), NULL);
}

void
_gum_module_registry_deactivate (GumModuleRegistry * self)
{
  if (gum_dyld_notifier_context != NULL)
  {
    GumDyldNotifierContext * context = gum_dyld_notifier_context;
    gum_dyld_notifier_context = NULL;

    *context->slot = context->original;
    g_slice_free (GumDyldNotifierContext, context);
  }

  g_clear_object (&gum_resolver);
}

static void
gum_module_registry_on_image_added (const struct mach_header * mh,
                                    intptr_t vmaddr_slide)
{
  gum_add_image (mh, NULL);
}

static void
gum_module_registry_on_image_removed (const struct mach_header * mh,
                                      intptr_t vmaddr_slide)
{
  gum_remove_image (mh);
}

static void
gum_lldb_image_notifier (enum dyld_image_mode mode,
                         guint32 info_count,
                         const struct dyld_image_info info[])
{
  uint32_t i;

  for (i = 0; i != info_count; i++)
  {
    if (mode == dyld_image_adding)
      gum_add_image (info[i].imageLoadAddress, NULL);
    else
      gum_remove_image (info[i].imageLoadAddress);
  }

  return gum_dyld_notifier_context->original (mode, info_count, info);
}

static void
gum_add_image (const struct mach_header * mh,
               const gchar * name)
{
  Dl_info info;
  GumMemoryRange range;
  GumNativeModule * mod;

  if (name == NULL)
    dladdr (mh, &info);

  range.base_address = GUM_ADDRESS (mh);
  range.size = gum_detect_macho_size (mh);

  mod = _gum_native_module_make ((name != NULL) ? name : info.dli_fname, &range,
      gum_resolver);

  _gum_module_registry_register (gum_registry, GUM_MODULE (mod));

  g_object_unref (mod);
}

static void
gum_remove_image (const struct mach_header * mh)
{
  _gum_module_registry_unregister (gum_registry, GUM_ADDRESS (mh));
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
