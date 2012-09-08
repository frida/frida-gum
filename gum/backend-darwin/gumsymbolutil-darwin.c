/*
 * Copyright (C) 2010-2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumsymbolutil.h"

#include "gumdarwin.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>

#define GUM_MAX_MACH_HEADER_SIZE (64 * 1024)

#define SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL(S) \
      (S->n_value == 0 || \
       S->n_type >= N_PEXT || \
       (S->n_type & N_EXT) == 0)

typedef struct _GumEnumerateModulesContext GumEnumerateModulesContext;
typedef struct _GumFindExportContext GumFindExportContext;
typedef struct _GumEnumerateExportsContext GumEnumerateExportsContext;

struct _GumEnumerateModulesContext
{
  mach_port_t task;
  GumFoundModuleFunc func;
  gpointer user_data;
  guint page_size;
};

struct _GumFindExportContext
{
  GumAddress result;
  const gchar * symbol_name;
};

struct _GumEnumerateExportsContext
{
  mach_port_t task;
  GHashTable * modules;
  const gchar * module_name;
  GumFoundExportFunc func;
  gpointer user_data;
};

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_LC_SEGMENT LC_SEGMENT
typedef struct mach_header gum_mach_header_t;
typedef struct segment_command gum_segment_command_t;
typedef struct nlist gum_nlist_t;
#else
# define GUM_LC_SEGMENT LC_SEGMENT_64
typedef struct mach_header_64 gum_mach_header_t;
typedef struct segment_command_64 gum_segment_command_t;
typedef struct nlist_64 gum_nlist_t;
#endif

typedef const struct dyld_all_image_infos * (* DyldGetAllImageInfosFunc) (
    void);

static gboolean gum_module_do_enumerate_exports (const gchar * module_name,
    GumFoundExportFunc func, gpointer user_data);
static gboolean gum_store_address_if_export_name_matches (const gchar * name,
    GumAddress address, gpointer user_data);
static gboolean gum_emit_if_range_is_a_module (const GumMemoryRange * range,
    GumPageProtection prot, gpointer user_data);

static gboolean gum_store_module_address (const gchar * name,
    GumAddress address, const gchar * path, gpointer user_data);
static gboolean gum_do_enumerate_exports (GumEnumerateExportsContext * ctx,
    const gchar * module_name);
static gboolean gum_darwin_find_slide (GumAddress module_address,
    guint8 * module, gsize module_size, gint64 * slide);
static gboolean gum_darwin_find_linkedit (guint8 * module, gsize module_size,
    GumAddress * linkedit);
static gboolean gum_darwin_find_symtab_command (guint8 * module,
    gsize module_size, struct symtab_command ** sc);

static gboolean find_image_address_and_slide (const gchar * image_name,
    gpointer * address, gpointer * slide);
static gboolean find_image_vmaddr_and_fileoff (gpointer address,
    gsize * vmaddr, gsize * fileoff);
static gboolean find_image_symtab_command (gpointer address,
    struct symtab_command ** sc);

static const char * gum_symbol_name_from_darwin (const char * s);

static DyldGetAllImageInfosFunc get_all_image_infos_impl = NULL;

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  const struct dyld_all_image_infos * all_info;
  guint count, i;

  if (get_all_image_infos_impl == NULL)
  {
    void * syslib;

    syslib = dlopen ("/usr/lib/libSystem.dylib", RTLD_LAZY | RTLD_GLOBAL);
    get_all_image_infos_impl = dlsym (syslib, "_dyld_get_all_image_infos");
    g_assert (get_all_image_infos_impl != NULL);
    dlclose (syslib);
  }

  all_info = get_all_image_infos_impl ();

  count = all_info->infoArrayCount;
  for (i = 0; i != count; i++)
  {
    const struct dyld_image_info * info = &all_info->infoArray[i];
    gchar * name;
    gboolean carry_on;

    name = g_path_get_basename (info->imageFilePath);
    carry_on = func (name, GUM_ADDRESS (info->imageLoadAddress),
        info->imageFilePath, user_data);
    g_free (name);

    if (!carry_on)
      break;
  }
}

void
gum_process_enumerate_ranges (GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  gum_darwin_enumerate_ranges (mach_task_self (), prot, func, user_data);
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  gum_module_do_enumerate_exports (module_name, func, user_data);
}

static gboolean
gum_module_do_enumerate_exports (const gchar * module_name,
                                 GumFoundExportFunc func,
                                 gpointer user_data)
{
  gpointer address, slide;
  gsize vmaddr, fileoff;
  struct symtab_command * sc;
  guint8 * table_base;
  gum_nlist_t * symbase, * sym;
  gchar * strbase;
  guint symbol_idx;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return TRUE;

  if (!find_image_vmaddr_and_fileoff (address, &vmaddr, &fileoff))
    return TRUE;

  if (!find_image_symtab_command (address, &sc))
    return TRUE;

  table_base = GSIZE_TO_POINTER (vmaddr - fileoff + GPOINTER_TO_SIZE (slide));
  symbase = (gum_nlist_t *) (table_base + sc->symoff);
  strbase = (gchar *) (table_base + sc->stroff);

  for (symbol_idx = 0, sym = symbase;
      symbol_idx != sc->nsyms;
      symbol_idx++, sym++)
  {
    const gchar * symbol_name;
    GumAddress symbol_address;

    if (SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL (sym))
      continue;

    symbol_name = gum_symbol_name_from_darwin (strbase + sym->n_un.n_strx);

    symbol_address = GUM_ADDRESS (
        GSIZE_TO_POINTER (sym->n_value) + GPOINTER_TO_SIZE (slide));
    if ((sym->n_desc & N_ARM_THUMB_DEF) != 0)
      symbol_address++;

    if (!func (symbol_name, symbol_address, user_data))
      return FALSE;
  }

  {
    gum_mach_header_t * header = address;
    guint8 * p;
    guint cmd_index;

    p = (guint8 *) (header + 1);
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      struct load_command * lc = (struct load_command *) p;

      if (lc->cmd == LC_REEXPORT_DYLIB)
      {
        struct dylib_command * dc = (struct dylib_command *) lc;
        const char * name = (const char *)
            (((guint8 *) dc) + dc->dylib.name.offset);
        if (!gum_module_do_enumerate_exports (name, func, user_data))
          return FALSE;
      }

      p += lc->cmdsize;
    }
  }

  return TRUE;
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  gpointer address, slide;
  gum_mach_header_t * header;
  guint8 * p;
  guint cmd_index;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return;

  header = address;
  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == GUM_LC_SEGMENT)
    {
      gum_segment_command_t * segcmd = (gum_segment_command_t *) lc;
      GumPageProtection cur_prot;

      cur_prot = gum_page_protection_from_mach (segcmd->initprot);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;

        range.base_address = GUM_ADDRESS (
            GSIZE_TO_POINTER (segcmd->vmaddr) + GPOINTER_TO_SIZE (slide));
        range.size = segcmd->vmsize;

        if (!func (&range, cur_prot, user_data))
          return;
      }
    }

    p += lc->cmdsize;
  }
}

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  gpointer address, slide;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return 0;

  return GUM_ADDRESS (address);
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumFindExportContext ctx;

  ctx.result = 0;
  ctx.symbol_name = symbol_name;

  gum_module_enumerate_exports (module_name,
      gum_store_address_if_export_name_matches, &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_export_name_matches (const gchar * name,
                                          GumAddress address,
                                          gpointer user_data)
{
  GumFindExportContext * ctx = (GumFindExportContext *) user_data;

  if (strcmp (name, ctx->symbol_name) == 0)
  {
    ctx->result = address;
    return FALSE;
  }

  return TRUE;
}

void
gum_darwin_enumerate_modules (mach_port_t task,
                              GumFoundModuleFunc func,
                              gpointer user_data)
{
  GumEnumerateModulesContext ctx;

  ctx.task = task;
  ctx.func = func;
  ctx.user_data = user_data;
  ctx.page_size = gum_query_page_size ();

  gum_darwin_enumerate_ranges (task, GUM_PAGE_RX,
      gum_emit_if_range_is_a_module, &ctx);
}

static gboolean
gum_emit_if_range_is_a_module (const GumMemoryRange * range,
                               GumPageProtection prot,
                               gpointer user_data)
{
  GumEnumerateModulesContext * ctx = user_data;
  gboolean carry_on = TRUE;
  guint8 * chunk, * page, * p;
  gsize chunk_size;

  chunk = gum_darwin_read (ctx->task, range->base_address, range->size,
      &chunk_size);
  if (chunk == NULL)
    return TRUE;

  g_assert (chunk_size % ctx->page_size == 0);

  for (page = chunk; page != chunk + chunk_size; page += ctx->page_size)
  {
    struct mach_header * header;
    guint cmd_index;

    header = (struct mach_header *) page;
    if (header->magic != MH_MAGIC && header->magic != MH_MAGIC_64)
      continue;

    if (header->filetype != MH_DYLIB)
      continue;

    if (header->magic == MH_MAGIC)
      p = page + sizeof (struct mach_header);
    else
      p = page + sizeof (struct mach_header_64);
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = (struct load_command *) p;

      if (lc->cmd == LC_ID_DYLIB)
      {
        const struct dylib * dl = &((struct dylib_command *) lc)->dylib;
        const gchar * raw_path;
        guint raw_path_len;
        gchar * path, * name;

        raw_path = (gchar *) p + dl->name.offset;
        raw_path_len = lc->cmdsize - sizeof (struct dylib_command);
        path = g_malloc (raw_path_len + 1);
        memcpy (path, raw_path, raw_path_len);
        path[raw_path_len] = '\0';
        name = g_path_get_basename (path);

        if (!ctx->func (name, range->base_address + (page - chunk), path,
            ctx->user_data))
        {
          carry_on = FALSE;
        }

        g_free (name);
        g_free (path);

        break;
      }

      p += lc->cmdsize;
    }

    if (!carry_on)
      break;
  }

  g_free (chunk);
  return carry_on;
}

void
gum_darwin_enumerate_ranges (mach_port_t task,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  mach_vm_address_t address = MACH_VM_MIN_ADDRESS;
  mach_vm_size_t size = (mach_vm_size_t) 0;
  natural_t depth = 0;

  while (TRUE)
  {
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr;
    GumPageProtection cur_prot;

    while (TRUE)
    {
      kr = mach_vm_region_recurse (task, &address, &size, &depth,
          (vm_region_recurse_info_t) &info, &info_count);
      if (kr != KERN_SUCCESS)
        break;

      if (info.is_submap)
      {
        depth++;
        continue;
      }
      else
      {
        break;
      }
    }

    if (kr != KERN_SUCCESS)
      break;

    cur_prot = gum_page_protection_from_mach (info.protection);

    if ((cur_prot & prot) == prot)
    {
      GumMemoryRange range;

      range.base_address = address;
      range.size = size;

      if (!func (&range, cur_prot, user_data))
        return;
    }

    address += size;
    size = 0;
  }
}

void
gum_darwin_enumerate_exports (mach_port_t task,
                              const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GumEnumerateExportsContext ctx;

  ctx.task = task;
  ctx.modules = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) g_variant_unref);
  ctx.module_name = module_name;
  ctx.func = func;
  ctx.user_data = user_data;

  gum_darwin_enumerate_modules (task, gum_store_module_address, &ctx);

  gum_do_enumerate_exports (&ctx, module_name);

  g_hash_table_unref (ctx.modules);
}

static gboolean
gum_store_module_address (const gchar * name,
                          GumAddress address,
                          const gchar * path,
                          gpointer user_data)
{
  GumEnumerateExportsContext * ctx = user_data;
  GVariant * value;

  value = g_variant_new_uint64 (address);
  g_hash_table_insert (ctx->modules, g_strdup (name), g_variant_ref (value));
  g_hash_table_insert (ctx->modules, g_strdup (path), g_variant_ref (value));
  g_variant_unref (value);

  return TRUE;
}

static gboolean
gum_do_enumerate_exports (GumEnumerateExportsContext * ctx,
                          const gchar * module_name)
{
  gboolean carry_on = TRUE;
  GumAddress address;
  guint8 * chunk = NULL;
  gsize chunk_size;
  struct mach_header * header;
  gint64 slide;
  GumAddress linkedit;
  struct symtab_command * sc;
  gsize symbol_size;
  guint8 * symbols = NULL;
  gchar * strings = NULL;
  guint8 * cur_sym;
  guint symbol_index;

  address = g_variant_get_uint64 (
      g_hash_table_lookup (ctx->modules, module_name));
  if (address == 0)
    goto beach;

  chunk = gum_darwin_read (ctx->task, address, GUM_MAX_MACH_HEADER_SIZE,
      &chunk_size);
  if (chunk == NULL)
    goto beach;
  header = (struct mach_header *) chunk;

  if (!gum_darwin_find_slide (address, chunk, chunk_size, &slide))
    goto beach;

  if (!gum_darwin_find_linkedit (chunk, chunk_size, &linkedit))
    goto beach;
  linkedit += slide;

  if (!gum_darwin_find_symtab_command (chunk, chunk_size, &sc))
    goto beach;

  if (header->magic == MH_MAGIC)
    symbol_size = sizeof (struct nlist);
  else
    symbol_size = sizeof (struct nlist_64);
  symbols = gum_darwin_read (ctx->task, linkedit + sc->symoff,
      sc->nsyms * symbol_size, NULL);
  if (symbols == NULL)
    goto beach;

  strings = (gchar *) gum_darwin_read (ctx->task,
      linkedit + sc->stroff, sc->strsize, NULL);
  if (strings == NULL)
    goto beach;

  cur_sym = symbols;
  for (symbol_index = 0; symbol_index != sc->nsyms; symbol_index++)
  {
    const gchar * symbol_name = NULL;
    GumAddress symbol_address = 0;

    if (header->magic == MH_MAGIC)
    {
      struct nlist * sym = (struct nlist *) cur_sym;
      if (!SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL (sym))
      {
        symbol_name = gum_symbol_name_from_darwin (strings + sym->n_un.n_strx);
        symbol_address = sym->n_value + slide;
        if ((sym->n_desc & N_ARM_THUMB_DEF) != 0)
          symbol_address++;
      }
    }
    else
    {
      struct nlist_64 * sym = (struct nlist_64 *) cur_sym;
      if (!SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL (sym))
      {
        symbol_name = gum_symbol_name_from_darwin (strings + sym->n_un.n_strx);
        symbol_address = sym->n_value + slide;
        if ((sym->n_desc & N_ARM_THUMB_DEF) != 0)
          symbol_address++;
      }
    }

    if (symbol_name != NULL)
    {
      if (!ctx->func (symbol_name, symbol_address, ctx->user_data))
      {
        carry_on = FALSE;
        break;
      }
    }

    cur_sym += symbol_size;
  }

  if (carry_on)
  {
    guint8 * cur_cmd;
    guint cmd_index;

    if (header->magic == MH_MAGIC)
      cur_cmd = chunk + sizeof (struct mach_header);
    else
      cur_cmd = chunk + sizeof (struct mach_header_64);
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      struct load_command * lc = (struct load_command *) cur_cmd;

      if (lc->cmd == LC_REEXPORT_DYLIB)
      {
        struct dylib_command * dc = (struct dylib_command *) lc;
        const char * name = (const char *)
            (((guint8 *) dc) + dc->dylib.name.offset);
        if (!gum_do_enumerate_exports (ctx, name))
        {
          carry_on = FALSE;
          break;
        }
      }

      cur_cmd += lc->cmdsize;
    }
  }

beach:
  g_free (strings);
  g_free (symbols);
  g_free (chunk);

  return carry_on;
}

static gboolean
gum_darwin_find_slide (GumAddress module_address,
                       guint8 * module,
                       gsize module_size,
                       gint64 * slide)
{
  struct mach_header * header;
  guint8 * p;
  guint cmd_index;

  header = (struct mach_header *) module;
  if (header->magic == MH_MAGIC)
    p = module + sizeof (struct mach_header);
  else
    p = module + sizeof (struct mach_header_64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      struct segment_command * sc = (struct segment_command *) lc;
      struct segment_command_64 * sc64 = (struct segment_command_64 *) lc;
      if (strcmp (sc->segname, "__TEXT") == 0)
      {
        if (header->magic == MH_MAGIC)
          *slide = module_address - sc->vmaddr;
        else
          *slide = module_address - sc64->vmaddr;
        return TRUE;
      }
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static gboolean
gum_darwin_find_linkedit (guint8 * module,
                          gsize module_size,
                          GumAddress * linkedit)
{
  struct mach_header * header;
  guint8 * p;
  guint cmd_index;

  header = (struct mach_header *) module;
  if (header->magic == MH_MAGIC)
    p = module + sizeof (struct mach_header);
  else
    p = module + sizeof (struct mach_header_64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64)
    {
      struct segment_command * sc = (struct segment_command *) lc;
      struct segment_command_64 * sc64 = (struct segment_command_64 *) lc;
      if (strcmp (sc->segname, "__LINKEDIT") == 0)
      {
        if (header->magic == MH_MAGIC)
          *linkedit = sc->vmaddr - sc->fileoff;
        else
          *linkedit = sc64->vmaddr - sc64->fileoff;
        return TRUE;
      }
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static gboolean
gum_darwin_find_symtab_command (guint8 * module,
                                gsize module_size,
                                struct symtab_command ** sc)
{
  struct mach_header * header;
  guint8 * p;
  guint cmd_index;

  header = (struct mach_header *) module;
  if (header->magic == MH_MAGIC)
    p = module + sizeof (struct mach_header);
  else
    p = module + sizeof (struct mach_header_64);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_SYMTAB)
    {
      *sc = (struct symtab_command *) lc;
      return TRUE;
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static gboolean
find_image_address_and_slide (const gchar * image_name,
                              gpointer * address,
                              gpointer * slide)
{
  gboolean name_is_absolute;
  guint count, idx;

  name_is_absolute = index (image_name, '/') != NULL;

  count = _dyld_image_count ();

  for (idx = 0; idx != count; idx++)
  {
    const gchar * name, * s;

    name = _dyld_get_image_name (idx);
    if (!name_is_absolute && (s = strrchr (name, '/')) != NULL)
      name = s + 1;

    if (strcmp (name, image_name) == 0)
    {
      *address = (gpointer) _dyld_get_image_header (idx);
      *slide = (gpointer) _dyld_get_image_vmaddr_slide (idx);
      return TRUE;
    }
  }

  return FALSE;
}

static gboolean
find_image_vmaddr_and_fileoff (gpointer address,
                               gsize * vmaddr,
                               gsize * fileoff)
{
  gum_mach_header_t * header = address;
  guint8 * p;
  guint cmd_index;

  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == GUM_LC_SEGMENT)
    {
      gum_segment_command_t * segcmd = (gum_segment_command_t *) lc;

      if (strcmp (segcmd->segname, "__LINKEDIT") == 0)
      {
        *vmaddr = segcmd->vmaddr;
        *fileoff = segcmd->fileoff;
        return TRUE;
      }
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static gboolean
find_image_symtab_command (gpointer address,
                           struct symtab_command ** sc)
{
  gum_mach_header_t * header = address;
  guint8 * p;
  guint cmd_index;

  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_SYMTAB)
    {
      *sc = (struct symtab_command *) lc;
      return TRUE;
    }

    p += lc->cmdsize;
  }

  return FALSE;
}

static const char *
gum_symbol_name_from_darwin (const char * s)
{
  return (s[0] == '_') ? s + 1 : s;
}
