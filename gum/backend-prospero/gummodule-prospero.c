/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodule-prospero.h"

#include <elf.h>
#include <ps5/kernel.h>
#include <string.h>

#define GUM_SELF_PROCESS (-1)

typedef struct _GumDynlibDynsec GumDynlibDynsec;
typedef struct _GumDynlibObj GumDynlibObj;
typedef struct _GumDynlibSymbols GumDynlibSymbols;

struct _GumDynlibDynsec
{
  struct
  {
    guint64 le_next;
    guint64 le_prev;
  } list_entry;

  guint64 sysvec;
  guint32 refcount;
  guint64 size;

  guint64 symtab;
  guint64 symtabsize;

  guint64 strtab;
  guint64 strtabsize;

  guint64 pltrela;
  guint64 pltrelasize;

  guint64 rela;
  guint64 relasize;

  guint64 hash;
  guint64 hashsize;

  guint64 dynamic;
  guint64 dynamicsize;

  guint64 sce_comment;
  guint64 sce_commentsize;

  guint64 sce_dynlib;
  guint64 sce_dynlibsize;

  guint64 unknown1;
  guint64 unknown1size;

  guint64 buckets;
  guint64 bucketssize;
  guint32 nbuckets;

  guint64 chains;
  guint64 chainssize;
  guint32 nchains;

  guint64 unknown2[7];
};

struct _GumDynlibObj
{
  guint64 next;
  guint64 path;
  guint64 unknown0[2];
  guint32 refcount;
  guint64 handle;

  guint64 mapbase;
  guint64 mapsize;
  guint64 textsize;

  guint64 database;
  guint64 datasize;

  guint64 unknown1;
  guint64 unknown1size;

  guint64 entry;
  guint64 unknown2;
  guint64 vaddrbase;

  guint32 tlsindex;
  guint64 tlsinit;
  guint64 tlsinitsize;
  guint64 tlssize;
  guint64 tlsoffset;
  guint64 tlsalign;

  guint64 pltgot;

  guint64 unknown3[6];

  guint64 init;
  guint64 fini;

  guint64 eh_frame_hdr;
  guint64 eh_frame_hdr_size;

  guint64 eh_frame;
  guint64 eh_frame_size;

  gint32 status;
  gint32 flags;

  guint64 unknown4[5];
  guint64 dynsec;
  guint64 unknown5[6];
};

struct _GumDynlibSymbols
{
  GumAddress mapbase;

  Elf64_Sym * entries;
  guint count;

  gchar * strings;
  gsize strings_size;
};

extern int kernel_dynlib_obj (pid_t pid, guint32 handle, GumDynlibObj * obj);

static gboolean gum_dynlib_symbols_load (GumDynlibSymbols * self,
    const gchar * path);
static void gum_dynlib_symbols_clear (GumDynlibSymbols * self);
static const gchar * gum_dynlib_symbols_get_name (const GumDynlibSymbols * self,
    const Elf64_Sym * symbol);

static gboolean gum_dynlib_obj_load (GumDynlibObj * self, const gchar * path);

void
_gum_prospero_module_enumerate_exports (const gchar * path,
                                        GumFoundExportFunc func,
                                        gpointer user_data)
{
  GumDynlibSymbols symbols;
  guint i;

  if (!gum_dynlib_symbols_load (&symbols, path))
    return;

  for (i = 0; i != symbols.count; i++)
  {
    const Elf64_Sym * symbol = &symbols.entries[i];
    guint8 bind = ELF64_ST_BIND (symbol->st_info);
    guint8 type = ELF64_ST_TYPE (symbol->st_info);
    GumExportDetails details;

    if (symbol->st_value == 0 || symbol->st_shndx == SHN_UNDEF)
      continue;

    if (bind != STB_GLOBAL && bind != STB_WEAK)
      continue;

    if (type == STT_FUNC)
      details.type = GUM_EXPORT_FUNCTION;
    else if (type == STT_OBJECT)
      details.type = GUM_EXPORT_VARIABLE;
    else
      continue;

    details.name = gum_dynlib_symbols_get_name (&symbols, symbol);
    details.address = symbols.mapbase + symbol->st_value;
    details.size = symbol->st_size;

    if (!func (&details, user_data))
      break;
  }

  gum_dynlib_symbols_clear (&symbols);
}

void
_gum_prospero_module_enumerate_symbols (const gchar * path,
                                        GumFoundSymbolFunc func,
                                        gpointer user_data)
{
  GumDynlibSymbols symbols;
  guint i;

  if (!gum_dynlib_symbols_load (&symbols, path))
    return;

  for (i = 0; i != symbols.count; i++)
  {
    const Elf64_Sym * symbol = &symbols.entries[i];
    guint8 bind = ELF64_ST_BIND (symbol->st_info);
    GumSymbolDetails details;

    details.is_global = bind == STB_GLOBAL || bind == STB_WEAK;

    switch (ELF64_ST_TYPE (symbol->st_info))
    {
      case STT_OBJECT:  details.type = GUM_SYMBOL_OBJECT;   break;
      case STT_FUNC:    details.type = GUM_SYMBOL_FUNCTION; break;
      case STT_SECTION: details.type = GUM_SYMBOL_SECTION;  break;
      case STT_FILE:    details.type = GUM_SYMBOL_FILE;     break;
      case STT_COMMON:  details.type = GUM_SYMBOL_COMMON;   break;
      case STT_TLS:     details.type = GUM_SYMBOL_TLS;      break;
      default:          details.type = GUM_SYMBOL_UNKNOWN;  break;
    }

    details.section = NULL;
    details.name = gum_dynlib_symbols_get_name (&symbols, symbol);
    details.address = symbols.mapbase + symbol->st_value;
    details.size = symbol->st_size;

    if (!func (&details, user_data))
      break;
  }

  gum_dynlib_symbols_clear (&symbols);
}

void
_gum_prospero_module_enumerate_sections (const gchar * path,
                                         GumFoundSectionFunc func,
                                         gpointer user_data)
{
  GumDynlibObj obj;
  GumSectionDetails text, data;

  if (!gum_dynlib_obj_load (&obj, path))
    return;

  text.id = "0.text";
  text.name = ".text";
  text.address = obj.mapbase;
  text.size = obj.textsize;

  if (!func (&text, user_data))
    return;

  data.id = "1.data";
  data.name = ".data";
  data.address = obj.database;
  data.size = obj.datasize;

  func (&data, user_data);
}

static gboolean
gum_dynlib_symbols_load (GumDynlibSymbols * self,
                         const gchar * path)
{
  GumDynlibObj obj;
  GumDynlibDynsec dynsec;

  if (!gum_dynlib_obj_load (&obj, path))
    return FALSE;

  if (kernel_copyout (obj.dynsec, &dynsec, sizeof (dynsec)) < 0)
    return FALSE;

  self->entries = g_malloc (dynsec.symtabsize);
  self->strings = g_malloc (dynsec.strtabsize);

  if (kernel_copyout (dynsec.symtab, self->entries, dynsec.symtabsize) < 0 ||
      kernel_copyout (dynsec.strtab, self->strings, dynsec.strtabsize) < 0)
  {
    gum_dynlib_symbols_clear (self);
    return FALSE;
  }

  self->mapbase = obj.mapbase;
  self->count = dynsec.symtabsize / sizeof (Elf64_Sym);
  self->strings_size = dynsec.strtabsize;

  return TRUE;
}

static void
gum_dynlib_symbols_clear (GumDynlibSymbols * self)
{
  g_clear_pointer (&self->entries, g_free);
  g_clear_pointer (&self->strings, g_free);
}

static const gchar *
gum_dynlib_symbols_get_name (const GumDynlibSymbols * self,
                             const Elf64_Sym * symbol)
{
  if (symbol->st_name >= self->strings_size)
    return "";

  return self->strings + symbol->st_name;
}

static gboolean
gum_dynlib_obj_load (GumDynlibObj * self,
                     const gchar * path)
{
  gboolean success = FALSE;
  gchar * name;
  guint32 handle;

  name = g_path_get_basename (path);

  if (kernel_dynlib_handle (GUM_SELF_PROCESS, name, &handle) >= 0)
    success = kernel_dynlib_obj (GUM_SELF_PROCESS, handle, self) >= 0;

  g_free (name);

  return success;
}
