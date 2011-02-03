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

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#if GLIB_SIZEOF_VOID_P == 4
typedef Elf32_Ehdr GumElfEHeader;
typedef Elf32_Shdr GumElfSHeader;
typedef Elf32_Sym GumElfSymbol;
# define GUM_ELF_ST_BIND(val) ELF32_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
#else
typedef Elf64_Ehdr GumElfEHeader;
typedef Elf64_Shdr GumElfSHeader;
typedef Elf64_Sym GumElfSymbol;
# define GUM_ELF_ST_BIND(val) ELF64_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF64_ST_TYPE(val)
#endif

#define GUM_MAPS_LINE_SIZE (1024 + PATH_MAX)

typedef struct _GumFindModuleContext GumFindModuleContext;

struct _GumFindModuleContext
{
  const gchar * module_name;
  gpointer base;
  gchar * path;
};

static gboolean gum_store_base_and_path_if_name_matches (const gchar * name,
    gpointer address, const gchar * path, gpointer user_data);

static GumPageProtection gum_page_protection_from_proc_perms_string (
    const gchar * perms);

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  FILE * fp;
  const guint line_size = GUM_MAPS_LINE_SIZE;
  gchar * line, * path, * prev_path;
  gboolean carry_on = TRUE;

  fp = fopen ("/proc/self/maps", "r");
  g_assert (fp != NULL);

  line = g_malloc (line_size);

  path = g_malloc (PATH_MAX);
  prev_path = g_malloc (PATH_MAX);
  prev_path[0] = '\0';

  while (carry_on && fgets (line, line_size, fp) != NULL)
  {
    const guint8 elf_magic[] = { 0x7f, 'E', 'L', 'F' };
    guint8 * start;
    gint n;
    gchar * name;

    n = sscanf (line, "%p-%*p %*s %*x %*s %*s %s", &start, path);
    if (n == 1)
      continue;
    g_assert_cmpint (n, ==, 2);

    if (strcmp (path, prev_path) == 0 || path[0] == '[')
      continue;
    else if (memcmp (start, elf_magic, sizeof (elf_magic)) != 0)
      continue;

    name = g_path_get_basename (path);
    carry_on = func (name, start, path, user_data);
    g_free (name);

    strcpy (prev_path, path);
  }

  g_free (path);
  g_free (prev_path);

  g_free (line);

  fclose (fp);
}

void
gum_process_enumerate_ranges (GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  FILE * fp;
  const guint line_size = GUM_MAPS_LINE_SIZE;
  gchar * line;
  gboolean carry_on = TRUE;

  fp = fopen ("/proc/self/maps", "r");
  g_assert (fp != NULL);

  line = g_malloc (line_size);

  while (carry_on && fgets (line, line_size, fp) != NULL)
  {
    guint8 * start, * end;
    gchar perms[4 + 1] = { 0, };
    gint n;
    GumPageProtection cur_prot;

    n = sscanf (line, "%p-%p %4s", &start, &end, perms);
    g_assert_cmpint (n, ==, 3);

    cur_prot = gum_page_protection_from_proc_perms_string (perms);

    if ((cur_prot & prot) == prot)
    {
      GumMemoryRange range;

      range.base_address = start;
      range.size = end - start;

      carry_on = func (&range, cur_prot, user_data);
    }
  }

  g_free (line);

  fclose (fp);
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GumFindModuleContext ctx = { module_name, NULL, NULL };
  gint fd = -1;
  gsize file_size;
  gpointer base_address = NULL;
  GumElfEHeader * ehdr;
  guint i;
  gsize dynsym_section_offset = 0, dynsym_section_size = 0;
  gsize dynsym_entry_size = 0;
  const gchar * dynsym_strtab = NULL;

  gum_process_enumerate_modules (gum_store_base_and_path_if_name_matches,
      &ctx);
  if (ctx.base == NULL)
    goto beach;

  fd = open (ctx.path, O_RDONLY);
  if (fd == -1)
    goto beach;

  file_size = lseek (fd, 0, SEEK_END);
  lseek (fd, 0, SEEK_SET);

  base_address = mmap (NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  g_assert (base_address != MAP_FAILED);

  ehdr = base_address;
  if (ehdr->e_type != ET_DYN)
    goto beach;

  for (i = 0; i != ehdr->e_shnum; i++)
  {
    GumElfSHeader * shdr;

    shdr = base_address + ehdr->e_shoff + (i * ehdr->e_shentsize);
    if (shdr->sh_type == SHT_DYNSYM)
    {
      GumElfSHeader * strtab_shdr;

      dynsym_section_offset = shdr->sh_offset;
      dynsym_section_size = shdr->sh_size;
      dynsym_entry_size = shdr->sh_entsize;

      strtab_shdr = base_address + ehdr->e_shoff +
          (shdr->sh_link * ehdr->e_shentsize);
      dynsym_strtab = base_address + strtab_shdr->sh_offset;

      g_assert_cmpuint (dynsym_section_size % dynsym_entry_size, ==, 0);
    }
  }

  if (dynsym_section_offset == 0)
    goto beach;

  for (i = 0; i != dynsym_section_size / dynsym_entry_size; i++)
  {
    GumElfSymbol * sym;

    sym = base_address + dynsym_section_offset + (i * dynsym_entry_size);
    if (GUM_ELF_ST_BIND (sym->st_info) == STB_GLOBAL &&
        GUM_ELF_ST_TYPE (sym->st_info) == STT_FUNC &&
        sym->st_shndx != SHN_UNDEF)
    {
      const gchar * name;
      gpointer address;

      name = dynsym_strtab + sym->st_name;
      address = ctx.base + sym->st_value;

      if (!func (name, address, user_data))
        goto beach;
    }
  }

beach:
  if (base_address != NULL)
    munmap (base_address, file_size);

  if (fd != -1)
    close (fd);

  g_free (ctx.path);
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  FILE * fp;
  const guint line_size = GUM_MAPS_LINE_SIZE;
  gchar * line, * path;
  gboolean carry_on = TRUE;

  fp = fopen ("/proc/self/maps", "r");
  g_assert (fp != NULL);

  line = g_malloc (line_size);
  path = g_malloc (PATH_MAX);

  while (carry_on && fgets (line, line_size, fp) != NULL)
  {
    guint8 * start, * end;
    gchar perms[4 + 1] = { 0, };
    gint n;
    gchar * name;

    n = sscanf (line, "%p-%p %4s %*x %*s %*s %s", &start, &end, perms, path);
    if (n == 3)
      continue;
    g_assert_cmpint (n, ==, 4);

    if (path[0] == '[')
      continue;

    name = g_path_get_basename (path);
    if (strcmp (name, module_name) == 0)
    {
      GumPageProtection cur_prot;

      cur_prot = gum_page_protection_from_proc_perms_string (perms);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;

        range.base_address = start;
        range.size = end - start;

        carry_on = func (&range, cur_prot, user_data);
      }
    }
    g_free (name);
  }

  g_free (path);
  g_free (line);

  fclose (fp);
}

gpointer
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * export_name)
{
  return NULL;
}

static gboolean
gum_store_base_and_path_if_name_matches (const gchar * name,
                                         gpointer address,
                                         const gchar * path,
                                         gpointer user_data)
{
  GumFindModuleContext * ctx = user_data;

  if (strcmp (name, ctx->module_name) != 0)
    return TRUE;

  ctx->base = address;
  ctx->path = g_strdup (path);
  return FALSE;
}

static GumPageProtection
gum_page_protection_from_proc_perms_string (const gchar * perms)
{
  GumPageProtection prot = GUM_PAGE_NO_ACCESS;

  if (perms[0] == 'r')
    prot |= GUM_PAGE_READ;
  if (perms[1] == 'w')
    prot |= GUM_PAGE_WRITE;
  if (perms[2] == 'x')
    prot |= GUM_PAGE_EXECUTE;

  return prot;
}
