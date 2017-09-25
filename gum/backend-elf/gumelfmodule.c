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
  guint type;

  self->fd = open (self->path, O_RDONLY);
  if (self->fd == -1)
    goto invalid_path;

  self->file_size = lseek (self->fd, 0, SEEK_END);
  lseek (self->fd, 0, SEEK_SET);

  self->data =
      mmap (NULL, self->file_size, PROT_READ, MAP_PRIVATE, self->fd, 0);
  if (self->data == MAP_FAILED)
    goto mmap_failed;

  self->ehdr = self->data;

  type = self->ehdr->e_type;
  if (type != ET_EXEC && type != ET_DYN)
    goto invalid_type;

  self->preferred_address = gum_elf_module_compute_preferred_address (self);

  self->valid = TRUE;
  return;

invalid_path:
  {
    goto error;
  }
mmap_failed:
  {
    self->data = NULL;
    goto error;
  }
invalid_type:
  {
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

  if (self->data != NULL)
    munmap (self->data, self->file_size);

  if (self->fd != -1)
    close (self->fd);

  g_free (self->path);

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
  if (module->fd == -1)
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
  gpointer data = self->data;
  GumElfEHeader * ehdr = self->ehdr;
  GumElfSHeader * dyn, * strtab_header;
  const gchar * strtab;
  gboolean carry_on;
  guint i;

  dyn = gum_elf_module_find_section_header (self, SHT_DYNAMIC);
  if (dyn == NULL)
    return;
  strtab_header = data + ehdr->e_shoff + (dyn->sh_link * ehdr->e_shentsize);
  strtab = data + strtab_header->sh_offset;

  carry_on = TRUE;
  for (i = 0; i != dyn->sh_size / dyn->sh_entsize && carry_on; i++)
  {
    GumElfDynamic * entry;

    entry = data + dyn->sh_offset + (i * dyn->sh_entsize);
    if (entry->d_tag == DT_NEEDED)
    {
      GumElfDependencyDetails details;

      details.name = strtab + entry->d_un.d_val;
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
  gpointer data = self->data;
  GumElfEHeader * ehdr = self->ehdr;
  GumElfSHeader * dynsym, * strtab_header;
  const gchar * strtab;
  gboolean carry_on;
  guint i;

  dynsym = gum_elf_module_find_section_header (self, SHT_DYNSYM);
  if (dynsym == NULL)
    return;
  strtab_header = data + ehdr->e_shoff + (dynsym->sh_link * ehdr->e_shentsize);
  strtab = data + strtab_header->sh_offset;

  carry_on = TRUE;
  for (i = 0; i != dynsym->sh_size / dynsym->sh_entsize && carry_on; i++)
  {
    GumElfSymbol * sym;
    GumElfSymbolDetails details;

    sym = data + dynsym->sh_offset + (i * dynsym->sh_entsize);

    details.name = strtab + sym->st_name;
    details.address =
        sym->st_value - self->preferred_address + self->base_address;
    details.type = GUM_ELF_ST_TYPE (sym->st_info);
    details.bind = GUM_ELF_ST_BIND (sym->st_info);
    details.section_header_index = sym->st_shndx;

    carry_on = func (&details, user_data);
  }
}

GumElfSHeader *
gum_elf_module_find_section_header (GumElfModule * self,
                                    GumElfSHeaderType type)
{
  GumElfEHeader * ehdr = self->ehdr;
  guint i;

  for (i = 0; i != ehdr->e_shnum; i++)
  {
    GumElfSHeader * shdr;

    shdr = self->data + ehdr->e_shoff + (i * ehdr->e_shentsize);
    if (shdr->sh_type == type)
      return shdr;
  }

  return NULL;
}

static GumAddress
gum_elf_module_compute_preferred_address (GumElfModule * self)
{
  GumElfEHeader * ehdr = self->ehdr;
  guint i;

  for (i = 0; i != ehdr->e_phnum; i++)
  {
    GumElfPHeader * phdr;

    phdr = self->data + ehdr->e_phoff + (i * ehdr->e_phentsize);
    if (phdr->p_offset == 0)
      return phdr->p_vaddr;
  }

  return 0;
}
