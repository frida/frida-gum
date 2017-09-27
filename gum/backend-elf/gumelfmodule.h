/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ELF_MODULE_H__
#define __GUM_ELF_MODULE_H__

#include <gelf.h>
#include <gum/gum.h>

G_BEGIN_DECLS

#define GUM_ELF_TYPE_MODULE (gum_elf_module_get_type ())
G_DECLARE_FINAL_TYPE (GumElfModule, gum_elf_module, GUM_ELF, MODULE, GObject)

typedef struct _GumElfDependencyDetails GumElfDependencyDetails;
typedef struct _GumElfSymbolDetails GumElfSymbolDetails;

typedef gboolean (* GumElfFoundDependencyFunc) (
    const GumElfDependencyDetails * details, gpointer user_data);
typedef gboolean (* GumElfFoundSymbolFunc) (const GumElfSymbolDetails * details,
    gpointer user_data);

typedef gsize GumElfSectionHeaderIndex;
typedef GElf_Word GumElfSectionHeaderType;
typedef guchar GumElfSymbolType;
typedef guchar GumElfSymbolBind;

struct _GumElfModule
{
  GObject parent;

  gboolean valid;
  gchar * name;
  gchar * path;

  gpointer file_data;
  gsize file_size;

  Elf * elf;

  GElf_Ehdr * ehdr;
  GElf_Ehdr ehdr_storage;

  GumAddress base_address;
  GumAddress preferred_address;
};

struct _GumElfDependencyDetails
{
  const gchar * name;
};

struct _GumElfSymbolDetails
{
  const gchar * name;
  GumAddress address;
  GumElfSymbolType type;
  GumElfSymbolBind bind;
  GumElfSectionHeaderIndex section_header_index;
};

GumElfModule * gum_elf_module_new_from_memory (const gchar * path,
    GumAddress base_address);

void gum_elf_module_enumerate_dependencies (GumElfModule * self,
    GumElfFoundDependencyFunc func, gpointer user_data);
void gum_elf_module_enumerate_imports (GumElfModule * self,
    GumFoundImportFunc func, gpointer user_data);
void gum_elf_module_enumerate_exports (GumElfModule * self,
    GumFoundExportFunc func, gpointer user_data);
void gum_elf_module_enumerate_dynamic_symbols (GumElfModule * self,
    GumElfFoundSymbolFunc func, gpointer user_data);
gboolean gum_elf_module_find_section_header (GumElfModule * self,
    GumElfSectionHeaderType type, Elf_Scn ** scn, GElf_Shdr * shdr);

G_END_DECLS

#endif
