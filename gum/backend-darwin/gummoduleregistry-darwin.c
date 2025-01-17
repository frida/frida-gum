/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry-priv.h"

#include "gum/gumdarwin.h"
#include "gummodule-darwin.h"
#if defined (HAVE_I386)
# include "gumx86reader.h"
#elif defined (HAVE_ARM64)
# include "gumarm64reader.h"
#endif

#include <dlfcn.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>

static void gum_module_registry_on_image_added (const struct mach_header * mh,
    intptr_t vmaddr_slide);
static void gum_module_registry_on_image_removed (const struct mach_header * mh,
    intptr_t vmaddr_slide);
static void gum_module_registry_on_dyld_notification (
    GumInvocationContext * context, gpointer user_data);

static void gum_add_image (const struct mach_header * mh, const gchar * name);
static void gum_remove_image (const struct mach_header * mh);

static gsize gum_detect_macho_size (const struct mach_header * mh);

static GumModuleRegistry * _the_registry;
static GumInterceptor * _the_interceptor;
static GumInvocationListener * _dyld_handler;

void
_gum_module_registry_activate (GumModuleRegistry * self)
{
  _the_registry = self;

  if (gum_process_get_teardown_requirement () == GUM_TEARDOWN_REQUIREMENT_FULL)
  {
    GumDarwinAllImageInfos infos;
    G_GNUC_UNUSED gconstpointer notification_impl;
    G_GNUC_UNUSED cs_insn * first_instruction;
    gsize offset = 0;
    uint32_t count, i;

    if (!gum_darwin_query_all_image_infos (mach_task_self (), &infos))
      return;

    notification_impl = GSIZE_TO_POINTER (
        gum_strip_code_address (infos.notification_address));

#if defined (HAVE_I386)
    first_instruction =
        gum_x86_reader_disassemble_instruction_at (notification_impl);
    if (first_instruction != NULL && first_instruction->id == X86_INS_INT3)
      offset = first_instruction->size;
#elif defined (HAVE_ARM64)
    first_instruction =
        gum_arm64_reader_disassemble_instruction_at (notification_impl);
    if (first_instruction != NULL && first_instruction->id == ARM64_INS_BRK)
      offset = first_instruction->size;
#endif

    _the_interceptor = gum_interceptor_obtain ();
    _dyld_handler = gum_make_probe_listener (
        gum_module_registry_on_dyld_notification, NULL, NULL);

    gum_interceptor_attach (_the_interceptor,
        (gpointer) (notification_impl + offset), _dyld_handler, NULL);

    do
    {
      _gum_module_registry_reset (_the_registry);

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
}

void
_gum_module_registry_deactivate (GumModuleRegistry * self)
{
  if (_dyld_handler != NULL)
  {
    gum_interceptor_detach (_the_interceptor, _dyld_handler);

    g_object_unref (_dyld_handler);
    _dyld_handler = NULL;

    g_object_unref (_the_interceptor);
    _the_interceptor = NULL;
  }
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
gum_module_registry_on_dyld_notification (GumInvocationContext * context,
                                          gpointer user_data)
{
  enum dyld_image_mode mode;
  uint32_t info_count;
  const struct dyld_image_info * info;
  uint32_t i;

  mode =
      GPOINTER_TO_SIZE (gum_invocation_context_get_nth_argument (context, 0));
  if (mode != dyld_image_adding && mode != dyld_image_removing)
    return;
  info_count =
      GPOINTER_TO_UINT (gum_invocation_context_get_nth_argument (context, 1));
  info = gum_invocation_context_get_nth_argument (context, 2);

  for (i = 0; i != info_count; i++)
  {
    if (mode == dyld_image_adding)
      gum_add_image (info[i].imageLoadAddress, NULL);
    else
      gum_remove_image (info[i].imageLoadAddress);
  }
}

static void
gum_add_image (const struct mach_header * mh,
               const gchar * name)
{
  Dl_info info;
  GumMemoryRange range;

  if (name == NULL)
    dladdr (mh, &info);

  range.base_address = GUM_ADDRESS (mh);
  range.size = gum_detect_macho_size (mh);

  _gum_module_registry_register (_the_registry,
      GUM_MODULE (_gum_native_module_make (
          (name != NULL) ? name : info.dli_fname,
          &range, NULL)));
}

static void
gum_remove_image (const struct mach_header * mh)
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
