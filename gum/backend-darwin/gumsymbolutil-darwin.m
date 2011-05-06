/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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
#include "gumsymbolutil-priv.h"

#import <Foundation/Foundation.h>
#import "VMUSymbolicator.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>

#define GUM_POOL_ALLOC() \
  NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init]
#define GUM_POOL_RELEASE() \
  [pool release]

#define SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL(S) \
      (S->n_value == 0 || \
       S->n_type >= N_PEXT || \
       (S->n_type & N_EXT) == 0)

typedef struct _GumFindExportContext GumFindExportContext;

struct _GumFindExportContext
{
  gpointer result;
  const gchar * symbol_name;
};

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_LC_SEGMENT LC_SEGMENT
typedef struct mach_header gum_mach_header_t;
typedef struct segment_command gum_segment_command_t;
#else
# define GUM_LC_SEGMENT LC_SEGMENT_64
typedef struct mach_header_64 gum_mach_header_t;
typedef struct segment_command_64 gum_segment_command_t;
#endif

typedef const struct dyld_all_image_infos * (* DyldGetAllImageInfosFunc) (
    void);

static gboolean gum_module_do_enumerate_exports (const gchar * module_name,
    GumFoundExportFunc func, gpointer user_data);
static gboolean gum_store_address_if_export_name_matches (const gchar * name,
    gpointer address, gpointer user_data);

#ifdef HAVE_SYMBOL_BACKEND
static gboolean gum_symbol_is_function (VMUSymbol * symbol);
#endif

static gboolean find_image_address_and_slide (const gchar * image_name,
    gpointer * address, gpointer * slide);
static gboolean find_image_vmaddr_and_fileoff (gpointer address,
    gsize * vmaddr, gsize * fileoff);
static gboolean find_image_symtab_command (gpointer address,
    struct symtab_command ** sc);

#ifdef HAVE_SYMBOL_BACKEND
static VMUSymbolicator * symbolicator = nil;
#endif
static DyldGetAllImageInfosFunc get_all_image_infos_impl = NULL;

void
_gum_symbol_util_init (void)
{
#ifdef HAVE_SYMBOL_BACKEND
  GUM_POOL_ALLOC ();
  symbolicator = [[VMUSymbolicator symbolicatorForTask: mach_task_self ()] retain];
  GUM_POOL_RELEASE ();
#endif
}

void
_gum_symbol_util_deinit (void)
{
#ifdef HAVE_SYMBOL_BACKEND
  GUM_POOL_ALLOC ();
  [symbolicator release];
  symbolicator = nil;
  GUM_POOL_RELEASE ();

  get_all_image_infos_impl = NULL;
#endif
}

#ifdef HAVE_SYMBOL_BACKEND

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumSymbolDetails * details)
{
  gboolean result = FALSE;
  VMUSymbol * symbol;
  VMUSourceInfo * info = nil;

  GUM_POOL_ALLOC ();

  symbol = [symbolicator symbolForAddress:GPOINTER_TO_SIZE (address)];
  if (symbol != nil)
    info = [symbol sourceInfoForAddress:GPOINTER_TO_SIZE (address)];
  if (info != nil)
  {
    details->address = address;
    strcpy (details->module_name, [[[symbol owner] name] UTF8String]);
    strcpy (details->symbol_name, [[symbol name] UTF8String]);
    strcpy (details->file_name, [[info fileName] UTF8String]);
    details->line_number = [info lineNumber];

    result = TRUE;
  }

  GUM_POOL_RELEASE ();

  return result;
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  gchar * result = NULL;
  VMUSymbol * symbol;

  GUM_POOL_ALLOC ();

  symbol = [symbolicator symbolForAddress:GPOINTER_TO_SIZE (address)];
  if (symbol != nil)
    result = g_strdup ([[symbol name] UTF8String]);

  GUM_POOL_RELEASE ();

  return result;
}

gpointer
gum_find_function (const gchar * name)
{
  gpointer result = NULL;
  NSArray * symbols;
  NSUInteger i;

  GUM_POOL_ALLOC ();

  symbols = [symbolicator symbolsForName:[NSString stringWithUTF8String:name]];
  for (i = 0; i != [symbols count]; i++)
  {
    VMUSymbol * symbol = [symbols objectAtIndex:i];

    if (gum_symbol_is_function (symbol))
    {
      result = GSIZE_TO_POINTER ([symbol addressRange].location);
      break;
    }
  }

  GUM_POOL_RELEASE ();

  return result;
}

GArray *
gum_find_functions_named (const gchar * name)
{
  GArray * result;
  NSArray * symbols;
  NSUInteger i;

  GUM_POOL_ALLOC ();

  result = g_array_new (FALSE, FALSE, sizeof (gpointer));

  symbols = [symbolicator symbolsForName:[NSString stringWithUTF8String:name]];
  for (i = 0; i != [symbols count]; i++)
  {
    VMUSymbol * symbol = [symbols objectAtIndex:i];

    if (gum_symbol_is_function (symbol))
    {
      gpointer address = GSIZE_TO_POINTER ([symbol addressRange].location);

      g_array_append_val (result, address);
    }
  }

  GUM_POOL_RELEASE ();

  return result;
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  GArray * result;
  GPatternSpec * pspec;
  NSArray * symbols;
  NSUInteger count, i;

  GUM_POOL_ALLOC ();

  result = g_array_new (FALSE, FALSE, sizeof (gpointer));

  pspec = g_pattern_spec_new (str);

  symbols = [symbolicator symbols];
  count = [symbols count];
  for (i = 0; i != count; i++)
  {
    VMUSymbol * symbol = [symbols objectAtIndex:i];

    if (gum_symbol_is_function (symbol))
    {
      const gchar * name = [[symbol name] UTF8String];

      if (g_pattern_match_string (pspec, name))
      {
        gpointer address = GSIZE_TO_POINTER ([symbol addressRange].location);

        g_array_append_val (result, address);
      }
    }
  }

  g_pattern_spec_free (pspec);

  GUM_POOL_RELEASE ();

  return result;
}

static gboolean
gum_symbol_is_function (VMUSymbol * symbol)
{
  return ([symbol isFunction] || [symbol isObjcMethod] ||
      [symbol isJavaMethod]);
}

#endif /* HAVE_SYMBOL_BACKEND */

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
    carry_on = func (name, (gpointer) info->imageLoadAddress,
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
  mach_port_t self;
  mach_vm_address_t address = MACH_VM_MIN_ADDRESS;
  mach_vm_size_t size = (mach_vm_size_t) 0;
  natural_t depth = 0;

  self = mach_task_self ();

  while (TRUE)
  {
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr;
    GumPageProtection cur_prot;

    while (TRUE)
    {
      kr = mach_vm_region_recurse (self, &address, &size, &depth,
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

      range.base_address = GSIZE_TO_POINTER (address);
      range.size = size;

      if (!func (&range, cur_prot, user_data))
        return;
    }

    address += size;
    size = 0;
  }
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
  gsize table_offset;
  struct nlist * symbase, * sym;
  gchar * strbase;
  guint symbol_count, symbol_idx;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return TRUE;

  if (!find_image_vmaddr_and_fileoff (address, &vmaddr, &fileoff))
    return TRUE;

  if (!find_image_symtab_command (address, &sc))
    return TRUE;

  table_offset = vmaddr - fileoff + GPOINTER_TO_SIZE (slide);
  symbase = (struct nlist *) (sc->symoff + table_offset);
  strbase = (gchar *) (sc->stroff + table_offset);

  symbol_count = sc->nsyms;
  for (symbol_idx = 0, sym = symbase;
      symbol_idx != symbol_count;
      symbol_idx++, sym++)
  {
    gchar * symbol_name;
    guint8 * symbol_address;

    if (SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL (sym))
      continue;

    symbol_name = strbase + sym->n_un.n_strx;
    if (symbol_name[0] == '_')
      symbol_name++;

    symbol_address = (guint8 *) GSIZE_TO_POINTER (sym->n_value);
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

        range.base_address = GSIZE_TO_POINTER (segcmd->vmaddr);
        range.size = segcmd->vmsize;

        if (!func (&range, cur_prot, user_data))
          return;
      }
    }

    p += lc->cmdsize;
  }
}

gpointer
gum_module_find_base_address (const gchar * module_name)
{
  gpointer address, slide;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return NULL;

  return address;
}

gpointer
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumFindExportContext ctx;

  ctx.result = NULL;
  ctx.symbol_name = symbol_name;

  gum_module_enumerate_exports (module_name,
      gum_store_address_if_export_name_matches, &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_export_name_matches (const gchar * name,
                                          gpointer address,
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

