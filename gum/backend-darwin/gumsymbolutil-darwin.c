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

#include "gumsymbolutil-priv.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>

#define SYMBOL_IS_UNDEFINED_DEBUG_OR_LOCAL(S) \
      (S->n_value == 0 || \
       S->n_type >= N_PEXT || \
       (S->n_type & N_EXT) == 0)

typedef const struct dyld_all_image_infos * (* DyldGetAllImageInfosFunc) (
    void);

static gboolean find_image_address_and_slide (const gchar * image_name,
    gpointer * address, gpointer * slide);
static gboolean find_image_vmaddr_and_fileoff (gpointer address,
    guint32 * vmaddr, guint32 * fileoff);
static gboolean find_image_symtab_command (gpointer address,
    struct symtab_command ** sc);

static DyldGetAllImageInfosFunc get_all_image_infos_impl = NULL;

void
_gum_symbol_util_init (void)
{
}

void
_gum_symbol_util_deinit (void)
{
  get_all_image_infos_impl = NULL;
}

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
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  gpointer address, slide;
  guint32 vmaddr, fileoff;
  struct symtab_command * sc;
  gsize table_offset;
  struct nlist * symbase, * sym;
  gchar * strbase;
  guint symbol_count, symbol_idx;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return;

  if (!find_image_vmaddr_and_fileoff (address, &vmaddr, &fileoff))
    return;

  if (!find_image_symtab_command (address, &sc))
    return;

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
      return;
  }
}

gpointer
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * export_name)
{
  return NULL;
}

static gboolean
find_image_address_and_slide (const gchar * image_name,
                              gpointer * address,
                              gpointer * slide)
{
  guint count, idx;

  count = _dyld_image_count ();

  for (idx = 0; idx != count; idx++)
  {
    const gchar * name, * s;

    name = _dyld_get_image_name (idx);
    if ((s = strrchr (name, '/')) != NULL)
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
                               guint32 * vmaddr,
                               guint32 * fileoff)
{
  struct mach_header * header = address;
  guint8 * p;
  guint cmd_index;

  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == LC_SEGMENT)
    {
      struct segment_command * segcmd = (struct segment_command *) lc;

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
  struct mach_header * header = address;
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

