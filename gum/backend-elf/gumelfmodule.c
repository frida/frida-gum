/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumelfmodule.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum
{
  PROP_0,
  PROP_NAME,
  PROP_PATH,
  PROP_BASE_ADDRESS
};

typedef struct _GumElfEnumerateImportsContext GumElfEnumerateImportsContext;
typedef struct _GumElfEnumerateExportsContext GumElfEnumerateExportsContext;

struct _GumElfEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;
};

struct _GumElfEnumerateExportsContext
{
  GumFoundExportFunc func;
  gpointer user_data;
};

static void gum_elf_module_constructed (GObject * object);
static void gum_elf_module_finalize (GObject * object);
static void gum_elf_module_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_elf_module_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gboolean gum_emit_elf_import (const GumElfSymbolDetails * details,
    gpointer user_data);
static gboolean gum_emit_elf_export (const GumElfSymbolDetails * details,
    gpointer user_data);

static void gum_elf_module_enumerate_symbols_in_section (GumElfModule * self,
    GumElfSectionHeaderType section, GumElfFoundSymbolFunc func,
    gpointer user_data);

static GumAddress gum_elf_module_compute_preferred_address (
    GumElfModule * self);

G_DEFINE_TYPE (GumElfModule, gum_elf_module, G_TYPE_OBJECT)

static void
gum_elf_module_class_init (GumElfModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_elf_module_constructed;
  object_class->finalize = gum_elf_module_finalize;
  object_class->get_property = gum_elf_module_get_property;
  object_class->set_property = gum_elf_module_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PATH,
      g_param_spec_string ("path", "Path", "Path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BASE_ADDRESS,
      g_param_spec_uint64 ("base-address", "BaseAddress", "Base address", 0,
      G_MAXUINT64, 0, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
gum_elf_module_init (GumElfModule * self)
{
}

static void
gum_elf_module_constructed (GObject * object)
{
  GumElfModule * self = GUM_ELF_MODULE (object);
  int fd;
  GElf_Half type;

  if (self->name == NULL)
  {
    self->name = g_path_get_basename (self->path);
  }

  fd = open (self->path, O_RDONLY);
  if (fd == -1)
    goto error;

  self->file_size = lseek (fd, 0, SEEK_END);
  lseek (fd, 0, SEEK_SET);

  self->file_data = mmap (NULL, self->file_size, PROT_READ, MAP_PRIVATE, fd, 0);

  close (fd);

  if (self->file_data == MAP_FAILED)
    goto mmap_failed;

  self->elf = elf_memory (self->file_data, self->file_size);
  if (self->elf == NULL)
    goto error;

  self->ehdr = gelf_getehdr (self->elf, &self->ehdr_storage);

  type = self->ehdr->e_type;
  if (type != ET_EXEC && type != ET_DYN)
    goto error;

  self->preferred_address = gum_elf_module_compute_preferred_address (self);

  self->valid = TRUE;
  return;

mmap_failed:
  {
    self->file_data = NULL;
    goto error;
  }
error:
  {
    self->valid = FALSE;
    return;
  }
}

static void
gum_elf_module_finalize (GObject * object)
{
  GumElfModule * self = GUM_ELF_MODULE (object);

  if (self->elf != NULL)
    elf_end (self->elf);

  if (self->file_data != NULL)
    munmap (self->file_data, self->file_size);

  g_free (self->path);
  g_free (self->name);

  G_OBJECT_CLASS (gum_elf_module_parent_class)->finalize (object);
}

static void
gum_elf_module_get_property (GObject * object,
                             guint property_id,
                             GValue * value,
                             GParamSpec * pspec)
{
  GumElfModule * self = GUM_ELF_MODULE (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_PATH:
      g_value_set_string (value, self->path);
      break;
    case PROP_BASE_ADDRESS:
      g_value_set_uint64 (value, self->base_address);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_elf_module_set_property (GObject * object,
                             guint property_id,
                             const GValue * value,
                             GParamSpec * pspec)
{
  GumElfModule * self = GUM_ELF_MODULE (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_PATH:
      g_free (self->path);
      self->path = g_value_dup_string (value);
      break;
    case PROP_BASE_ADDRESS:
      self->base_address = g_value_get_uint64 (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumElfModule *
gum_elf_module_new_from_memory (const gchar * path,
                                GumAddress base_address)
{
  GumElfModule * module;

  module = g_object_new (GUM_ELF_TYPE_MODULE,
      "path", path,
      "base-address", base_address,
      NULL);
  if (!module->valid)
  {
    g_object_unref (module);
    return NULL;
  }

  return module;
}

void
gum_elf_module_enumerate_dependencies (GumElfModule * self,
                                       GumElfFoundDependencyFunc func,
                                       gpointer user_data)
{
  Elf_Scn * scn;
  GElf_Shdr shdr;
  gboolean carry_on;
  GElf_Word item_count, item_index;
  Elf_Data * data;

  if (!gum_elf_module_find_section_header (self, SHT_DYNAMIC, &scn, &shdr))
    return;

  carry_on = TRUE;
  item_count = shdr.sh_size / shdr.sh_entsize;
  data = elf_getdata (scn, NULL);

  for (item_index = 0;
      item_index != item_count && carry_on;
      item_index++)
  {
    GElf_Dyn dyn;

    gelf_getdyn (data, item_index, &dyn);

    if (dyn.d_tag == DT_NEEDED)
    {
      GumElfDependencyDetails details;

      details.name = elf_strptr (self->elf, shdr.sh_link, dyn.d_un.d_val);

      carry_on = func (&details, user_data);
    }
  }
}

void
gum_elf_module_enumerate_imports (GumElfModule * self,
                                  GumFoundImportFunc func,
                                  gpointer user_data)
{
  GumElfEnumerateImportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_dynamic_symbols (self, gum_emit_elf_import, &ctx);
}

static gboolean
gum_emit_elf_import (const GumElfSymbolDetails * details,
                     gpointer user_data)
{
  GumElfEnumerateImportsContext * ctx = user_data;

  if (details->section_header_index == SHN_UNDEF &&
      (details->type == STT_FUNC || details->type == STT_OBJECT))
  {
    GumImportDetails d;

    d.type = (details->type == STT_FUNC)
        ? GUM_EXPORT_FUNCTION
        : GUM_EXPORT_VARIABLE;
    d.name = details->name;
    d.module = NULL;
    d.address = 0;

    if (!ctx->func (&d, ctx->user_data))
      return FALSE;
  }

  return TRUE;
}

void
gum_elf_module_enumerate_exports (GumElfModule * self,
                                  GumFoundExportFunc func,
                                  gpointer user_data)
{
  GumElfEnumerateExportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_dynamic_symbols (self, gum_emit_elf_export, &ctx);
}

static gboolean
gum_emit_elf_export (const GumElfSymbolDetails * details,
                     gpointer user_data)
{
  GumElfEnumerateExportsContext * ctx = user_data;

  if (details->section_header_index != SHN_UNDEF &&
      (details->type == STT_FUNC || details->type == STT_OBJECT) &&
      (details->bind == STB_GLOBAL || details->bind == STB_WEAK))
  {
    GumExportDetails d;

    d.type = (details->type == STT_FUNC)
        ? GUM_EXPORT_FUNCTION
        : GUM_EXPORT_VARIABLE;
    d.name = details->name;
    d.address = details->address;

    if (!ctx->func (&d, ctx->user_data))
      return FALSE;
  }

  return TRUE;
}

void
gum_elf_module_enumerate_dynamic_symbols (GumElfModule * self,
                                          GumElfFoundSymbolFunc func,
                                          gpointer user_data)
{
  gum_elf_module_enumerate_symbols_in_section (self, SHT_DYNSYM, func,
      user_data);
}

void
gum_elf_module_enumerate_symbols (GumElfModule * self,
                                  GumElfFoundSymbolFunc func,
                                  gpointer user_data)
{
  gum_elf_module_enumerate_symbols_in_section (self, SHT_SYMTAB, func,
      user_data);
}

static void
gum_elf_module_enumerate_symbols_in_section (GumElfModule * self,
                                             GumElfSectionHeaderType section,
                                             GumElfFoundSymbolFunc func,
                                             gpointer user_data)
{
  Elf_Scn * scn;
  GElf_Shdr shdr;
  gboolean carry_on;
  GElf_Word symbol_count, symbol_index;
  Elf_Data * data;

  if (!gum_elf_module_find_section_header (self, section, &scn, &shdr))
    return;

  carry_on = TRUE;
  symbol_count = shdr.sh_size / shdr.sh_entsize;
  data = elf_getdata (scn, NULL);

  for (symbol_index = 0;
      symbol_index != symbol_count && carry_on;
      symbol_index++)
  {
    GElf_Sym sym;
    GumElfSymbolDetails details;

    gelf_getsym (data, symbol_index, &sym);

    details.name = elf_strptr (self->elf, shdr.sh_link, sym.st_name);
    details.address = self->base_address +
        (sym.st_value - self->preferred_address);
    details.type = GELF_ST_TYPE (sym.st_info);
    details.bind = GELF_ST_BIND (sym.st_info);
    details.section_header_index = sym.st_shndx;

    carry_on = func (&details, user_data);
  }
}

gboolean
gum_elf_module_find_section_header (GumElfModule * self,
                                    GumElfSectionHeaderType type,
                                    Elf_Scn ** scn,
                                    GElf_Shdr * shdr)
{
  Elf_Scn * cur = NULL;

  while ((cur = elf_nextscn (self->elf, cur)) != NULL)
  {
    gelf_getshdr (cur, shdr);

    if (shdr->sh_type == type)
    {
      *scn = cur;
      return TRUE;
    }
  }

  return FALSE;
}

static GumAddress
gum_elf_module_compute_preferred_address (GumElfModule * self)
{
  GElf_Half header_count, header_index;

  header_count = self->ehdr->e_phnum;

  for (header_index = 0; header_index != header_count; header_index++)
  {
    GElf_Phdr phdr;

    gelf_getphdr (self->elf, header_index, &phdr);

    if (phdr.p_offset == 0)
      return phdr.p_vaddr;
  }

  return 0;
}
