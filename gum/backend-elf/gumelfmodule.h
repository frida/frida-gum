/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ELF_MODULE_H__
#define __GUM_ELF_MODULE_H__

#include <elf.h>
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

typedef guint GumElfSHeaderIndex;
typedef guint GumElfSHeaderType;
typedef guint GumElfSymbolType;
typedef guint GumElfSymbolBind;
#if GLIB_SIZEOF_VOID_P == 4
typedef Elf32_Ehdr GumElfEHeader;
typedef Elf32_Phdr GumElfPHeader;
typedef Elf32_Shdr GumElfSHeader;
typedef Elf32_Dyn GumElfDynamic;
typedef Elf32_Sym GumElfSymbol;
# define GUM_ELF_ST_BIND(val) ELF32_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
#else
typedef Elf64_Ehdr GumElfEHeader;
typedef Elf64_Phdr GumElfPHeader;
typedef Elf64_Shdr GumElfSHeader;
typedef Elf64_Dyn GumElfDynamic;
typedef Elf64_Sym GumElfSymbol;
# define GUM_ELF_ST_BIND(val) ELF64_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF64_ST_TYPE(val)
#endif

struct _GumElfModule
{
  GObject parent;

  gboolean valid;
  gchar * name;
  gchar * path;
  gint fd;
  gsize file_size;
  gpointer data;
  GumElfEHeader * ehdr;
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
  GumElfSHeaderIndex section_header_index;
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
GumElfSHeader * gum_elf_module_find_section_header (GumElfModule * self,
    GumElfSHeaderType type);

G_END_DECLS

#endif
