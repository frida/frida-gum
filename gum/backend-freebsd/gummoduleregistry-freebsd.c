/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry-elf.h"

#include "gummodule-elf.h"
#if defined (HAVE_I386)
# include "gumx86reader.h"
#elif defined (HAVE_ARM64)
# include "gumarm64reader.h"
#endif

#include <dlfcn.h>
#include <link.h>

typedef struct _GumEnumerateModulesContext GumEnumerateModulesContext;

struct _GumEnumerateModulesContext
{
  GumFoundModuleFunc func;
  gpointer user_data;
};

static int gum_emit_module_from_phdr (struct dl_phdr_info * info, size_t size,
    void * user_data);
static gpointer gum_create_module_handle (GumNativeModule * module,
    gpointer user_data);
static int gum_find_r_debug (struct dl_phdr_info * info, size_t size,
    void * user_data);
static gboolean gum_find_debug_entry (const GumElfDynamicEntryDetails * details,
    gpointer user_data);
static gpointer gum_find_dlopen_object (const struct r_debug * dbg);
static gboolean gum_find_text_range (const GumElfSegmentDetails * details,
    gpointer user_data);
static gboolean gum_store_first_match (GumAddress address, gsize size,
    gpointer user_data);

static GumAddress gum_compute_elf_base_address_from_phdr_info (
    const struct dl_phdr_info * info);
static gsize gum_compute_elf_size_from_program_headers (
    const ElfW(Phdr) * headers, ElfW(Half) num_headers);

void
_gum_module_registry_enumerate_loaded_modules (GumFoundModuleFunc func,
                                               gpointer user_data)
{
  GumEnumerateModulesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  dl_iterate_phdr (gum_emit_module_from_phdr, &ctx);
}

static int
gum_emit_module_from_phdr (struct dl_phdr_info * info,
                           size_t size,
                           void * user_data)
{
  GumEnumerateModulesContext * ctx = user_data;
  GumMemoryRange range;
  gboolean carry_on;
  GumNativeModule * module;

  range.base_address = gum_compute_elf_base_address_from_phdr_info (info);
  range.size = gum_compute_elf_size_from_program_headers (info->dlpi_phdr,
      info->dlpi_phnum);

  module = _gum_native_module_make (info->dlpi_name, &range,
      gum_create_module_handle, NULL, NULL, (GDestroyNotify) dlclose);

  carry_on = ctx->func (GUM_MODULE (module), ctx->user_data);

  g_object_unref (module);

  return carry_on ? 0 : 1;
}

static gpointer
gum_create_module_handle (GumNativeModule * module,
                          gpointer user_data)
{
  return dlopen (module->path, RTLD_LAZY | RTLD_NOLOAD);
}

void
_gum_module_registry_enumerate_rtld_notifiers (GumFoundRtldNotifierFunc func,
                                               gpointer user_data)
{
  struct r_debug * dbg = NULL;
  GumRtldNotifierDetails notifier;

  dl_iterate_phdr (gum_find_r_debug, &dbg);
  g_assert (dbg != NULL);

  notifier.point_cut = GUM_POINT_LEAVE;

  notifier.location = gum_find_dlopen_object (dbg);
  func (&notifier, user_data);

  notifier.location = dlsym (RTLD_DEFAULT, "dlclose");
  func (&notifier, user_data);
}

static int
gum_find_r_debug (struct dl_phdr_info * info,
                  size_t size,
                  void * user_data)
{
  struct r_debug ** dbg = user_data;
  GumElfModule * elf;

  elf = gum_elf_module_new_from_memory (info->dlpi_name,
      gum_compute_elf_base_address_from_phdr_info (info), NULL);

  gum_elf_module_enumerate_dynamic_entries (elf, gum_find_debug_entry, dbg);

  g_object_unref (elf);

  return (*dbg == NULL) ? 0 : 1;
}

static gboolean
gum_find_debug_entry (const GumElfDynamicEntryDetails * details,
                      gpointer user_data)
{
  struct r_debug ** dbg = user_data;

  if (details->tag == GUM_ELF_DYNAMIC_DEBUG)
  {
    *dbg = GSIZE_TO_POINTER (details->val);
    return FALSE;
  }

  return TRUE;
}

static gpointer
gum_find_dlopen_object (const struct r_debug * dbg)
{
  GumElfModule * elf;
  GumMemoryRange text;
  GumMatchPattern * setup_flags_arg;
  gpointer location;

  elf = gum_elf_module_new_from_memory ("/libexec/ld-elf.so.1",
      GUM_ADDRESS (dbg->r_ldbase), NULL);
  gum_elf_module_enumerate_segments (elf, gum_find_text_range, &text);
  text.base_address += GUM_ADDRESS (dbg->r_ldbase);
  g_object_unref (elf);

#if defined (HAVE_I386)
  setup_flags_arg = gum_match_pattern_new_from_string ("41 81 e7 03 01 00 00");
#elif defined (HAVE_ARM64)
  setup_flags_arg = gum_match_pattern_new_from_string ("68 20 80 52");
#else
# error Unsupported architecture
#endif

  location = NULL;
  gum_memory_scan (&text, setup_flags_arg, gum_store_first_match, &location);
  g_assert (location != NULL);

  gum_match_pattern_unref (setup_flags_arg);

#if defined (HAVE_I386)
  return gum_x86_reader_find_next_call_target (location);
#elif defined (HAVE_ARM64)
  return gum_arm64_reader_find_next_bl_target (location);
#else
# error Unsupported architecture
#endif
}

static gboolean
gum_find_text_range (const GumElfSegmentDetails * details,
                     gpointer user_data)
{
  GumMemoryRange * text = user_data;

  if ((details->protection & GUM_PAGE_EXECUTE) != 0)
  {
    text->base_address = details->vm_address;
    text->size = details->vm_size;
    return FALSE;
  }

  return TRUE;
}

static gboolean
gum_store_first_match (GumAddress address,
                       gsize size,
                       gpointer user_data)
{
  gpointer * location = user_data;

  *location = GSIZE_TO_POINTER (address);

  return FALSE;
}

void
_gum_module_registry_handle_rtld_notification (GumSynchronizeModulesFunc sync,
                                               GumInvocationContext * ic)
{
  sync ();
}

static GumAddress
gum_compute_elf_base_address_from_phdr_info (const struct dl_phdr_info * info)
{
  gboolean is_program_itself;

  is_program_itself = info->dlpi_addr == 0;

  if (is_program_itself)
  {
    gsize page_size_mask = ~((gsize) gum_query_page_size () - 1);
    return GPOINTER_TO_SIZE (info->dlpi_phdr) & page_size_mask;
  }

  return info->dlpi_addr;
}

static gsize
gum_compute_elf_size_from_program_headers (const ElfW(Phdr) * headers,
                                           ElfW(Half) num_headers)
{
  gsize total_size = 0;
  Elf_Half i;

  for (i = 0; i != num_headers; i++)
  {
    const Elf_Phdr * h = &headers[i];
    if (h->p_type == PT_LOAD)
      total_size += h->p_memsz;
  }

  return total_size;
}
