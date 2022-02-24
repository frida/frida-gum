/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2019 Jon Wilson <jonwilson@zepler.net>
 * Copyright (C)      2021 Paul Schmidt <p.schmidt@tu-bs.de>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumelfmodule.h"

#ifdef HAVE_ANDROID
# include "backend-linux/gumandroid.h"
# ifdef HAVE_MINIZIP
#  include <minizip/mz.h>
#  include <minizip/mz_strm.h>
#  include <minizip/mz_strm_os.h>
#  include <minizip/mz_zip.h>
#  include <minizip/mz_zip_rw.h>
# endif
#endif

#include <fcntl.h>
#include <gelf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef guint GumElfSource;
typedef guint GumElfDynamicAddressState;
typedef guint32 GumElfSectionHeaderType;
typedef struct _GumElfEnumerateDepsContext GumElfEnumerateDepsContext;
typedef struct _GumElfEnumerateImportsContext GumElfEnumerateImportsContext;
typedef struct _GumElfEnumerateExportsContext GumElfEnumerateExportsContext;
typedef struct _GumElfStoreSymtabParamsContext GumElfStoreSymtabParamsContext;

enum
{
  PROP_0,
  PROP_MODE,
  PROP_NAME,
  PROP_PATH,
  PROP_BASE_ADDRESS,
  PROP_PREFERRED_ADDRESS,
  PROP_ENTRYPOINT,
};

struct _GumElfModule
{
  GObject parent;

  GumElfMode mode;
  gchar * name;
  gchar * path;

  gpointer file_data;
  gsize file_size;
  GumElfSource source;

  Elf * elf;

  GElf_Ehdr * ehdr;
  GElf_Ehdr ehdr_storage;

  GumAddress base_address;
  GumAddress preferred_address;
  GumElfDynamicAddressState dynamic_address_state;

  const gchar * dynamic_strings;
};

enum _GumElfSource
{
  GUM_ELF_SOURCE_NONE,
  GUM_ELF_SOURCE_FILE,
  GUM_ELF_SOURCE_BLOB,
  GUM_ELF_SOURCE_VDSO,
};

enum _GumElfDynamicAddressState
{
  GUM_ELF_DYNAMIC_ADDRESS_PRISTINE,
  GUM_ELF_DYNAMIC_ADDRESS_ADJUSTED,
};

struct _GumElfEnumerateDepsContext
{
  GumFoundElfDependencyFunc func;
  gpointer user_data;

  GumElfModule * module;
};

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

struct _GumElfStoreSymtabParamsContext
{
  guint pending;
  gboolean found_hash;

  gpointer entries;
  gsize entry_size;
  gsize entry_count;

  GumElfModule * module;
};

struct _GumElfStoreFindStringTableContext
{
  GumElfModule * module;
};

static void gum_elf_module_constructed (GObject * object);
static void gum_elf_module_finalize (GObject * object);
static void gum_elf_module_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_elf_module_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static void gum_elf_module_unload (GumElfModule * self);
static gboolean gum_emit_each_needed (const GumElfDynamicEntryDetails * details,
    gpointer user_data);
static gboolean gum_emit_elf_import (const GumElfSymbolDetails * details,
    gpointer user_data);
static gboolean gum_emit_elf_export (const GumElfSymbolDetails * details,
    gpointer user_data);
static gboolean gum_store_symtab_params (
    const GumElfDynamicEntryDetails * details, gpointer user_data);
static gboolean gum_adjust_symtab_params (const GumElfSectionDetails * details,
    gpointer user_data);
static void gum_elf_module_enumerate_symbols_in_section (GumElfModule * self,
    GumElfSectionHeaderType section, GumFoundElfSymbolFunc func,
    gpointer user_data);
static gboolean gum_elf_module_find_load_phdr_by_address (GumElfModule * self,
    GumAddress address, GElf_Phdr * phdr);
static gboolean gum_elf_module_find_dynamic_phdr (GumElfModule * self,
    GElf_Phdr * phdr);
static gboolean gum_elf_module_find_section_header_by_index (
    GumElfModule * self, guint index, Elf_Scn ** scn, GElf_Shdr * shdr);
static gboolean gum_elf_module_find_section_header_by_type (GumElfModule * self,
    GumElfSectionHeaderType type, Elf_Scn ** scn, GElf_Shdr * shdr);
static GumAddress gum_elf_module_compute_preferred_address (
    GumElfModule * self);
static GumElfDynamicAddressState gum_elf_module_detect_dynamic_address_state (
    GumElfModule * self);
static gpointer gum_elf_module_resolve_dynamic_virtual_location (
    GumElfModule * self, GumAddress address);
static gboolean gum_store_dynamic_string_table (
    const GumElfDynamicEntryDetails * details, gpointer user_data);
static gboolean gum_maybe_extract_from_apk (const gchar * path,
    gpointer * file_data, gsize * file_size);


G_DEFINE_TYPE (GumElfModule, gum_elf_module, G_TYPE_OBJECT)

static void
gum_elf_module_class_init (GumElfModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_elf_module_constructed;
  object_class->finalize = gum_elf_module_finalize;
  object_class->get_property = gum_elf_module_get_property;
  object_class->set_property = gum_elf_module_set_property;

  g_object_class_install_property (object_class, PROP_MODE,
      g_param_spec_enum ("mode", "Mode", "Mode", GUM_TYPE_ELF_MODE,
      GUM_ELF_MODE_OFFLINE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PATH,
      g_param_spec_string ("path", "Path", "Path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BASE_ADDRESS,
      g_param_spec_uint64 ("base-address", "Base Address",
      "Base virtual address, or zero when operating offline", 0,
      G_MAXUINT64, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PREFERRED_ADDRESS,
      g_param_spec_uint64 ("preferred-address", "Preferred Address",
      "Preferred virtual address", 0, G_MAXUINT64, 0, G_PARAM_READABLE |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_ENTRYPOINT,
      g_param_spec_uint64 ("entrypoint", "Entrypoint",
      "Entrypoint virtual address", 0, G_MAXUINT64, 0, G_PARAM_READABLE |
      G_PARAM_STATIC_STRINGS));

  elf_version (EV_CURRENT);
}

static void
gum_elf_module_init (GumElfModule * self)
{
  self->source = GUM_ELF_SOURCE_NONE;
}

static void
gum_elf_module_constructed (GObject * object)
{
  GumElfModule * self = GUM_ELF_MODULE (object);

  if (self->name == NULL)
  {
    self->name = g_path_get_basename (self->path);
  }
}

static void
gum_elf_module_finalize (GObject * object)
{
  GumElfModule * self = GUM_ELF_MODULE (object);

  gum_elf_module_unload (self);

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
    case PROP_MODE:
      g_value_set_enum (value, self->mode);
      break;
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_PATH:
      g_value_set_string (value, self->path);
      break;
    case PROP_BASE_ADDRESS:
      g_value_set_uint64 (value, self->base_address);
      break;
    case PROP_PREFERRED_ADDRESS:
      g_value_set_uint64 (value, self->preferred_address);
      break;
    case PROP_ENTRYPOINT:
      g_value_set_uint64 (value, gum_elf_module_get_entrypoint (self));
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
    case PROP_MODE:
      self->mode = g_value_get_enum (value);
      break;
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
gum_elf_module_new_from_file (const gchar * path,
                              GError ** error)
{
  GumElfModule * module;

  module = g_object_new (GUM_ELF_TYPE_MODULE,
      "mode", GUM_ELF_MODE_OFFLINE,
      "path", path,
      NULL);
  if (!gum_elf_module_load (module, error))
  {
    g_object_unref (module);
    return NULL;
  }

  return module;
}

GumElfModule *
gum_elf_module_new_from_memory (const gchar * path,
                                GumAddress base_address,
                                GError ** error)
{
  GumElfModule * module;

  module = g_object_new (GUM_ELF_TYPE_MODULE,
      "mode", GUM_ELF_MODE_ONLINE,
      "path", path,
      "base-address", base_address,
      NULL);
  if (!gum_elf_module_load (module, error))
  {
    g_object_unref (module);
    return NULL;
  }

  return module;
}

gboolean
gum_elf_module_load (GumElfModule * self,
                     GError ** error)
{
  GElf_Half type;

  if (self->source != GUM_ELF_SOURCE_NONE)
    return TRUE;

#ifdef HAVE_LINUX
  if (self->mode == GUM_ELF_MODE_ONLINE &&
      strcmp (self->path, "linux-vdso.so.1") == 0)
  {
    self->source = GUM_ELF_SOURCE_VDSO;
    self->file_data = GSIZE_TO_POINTER (self->base_address);
    self->file_size = gum_query_page_size ();
  }
  else
#endif
  if (gum_maybe_extract_from_apk (self->path, &self->file_data,
      &self->file_size))
  {
    self->source = GUM_ELF_SOURCE_BLOB;
  }
  else
  {
    int fd;

    self->source = GUM_ELF_SOURCE_FILE;

    fd = open (self->path, O_RDONLY);
    if (fd == -1)
      goto error;

    self->file_size = lseek (fd, 0, SEEK_END);
    lseek (fd, 0, SEEK_SET);

    self->file_data =
        mmap (NULL, self->file_size, PROT_READ, MAP_PRIVATE, fd, 0);

    close (fd);

    if (self->file_data == MAP_FAILED)
      goto mmap_failed;
  }

  self->elf = elf_memory (self->file_data, self->file_size);
  if (self->elf == NULL)
    goto error;

  self->ehdr = gelf_getehdr (self->elf, &self->ehdr_storage);
  if (self->ehdr == NULL)
    goto error;

  type = self->ehdr->e_type;
  if (type != ET_EXEC && type != ET_DYN)
    goto error;

  self->preferred_address = gum_elf_module_compute_preferred_address (self);

  self->dynamic_address_state =
      gum_elf_module_detect_dynamic_address_state (self);

  gum_elf_module_enumerate_dynamic_entries (self,
      gum_store_dynamic_string_table, self);

  return TRUE;

mmap_failed:
  {
    self->file_data = NULL;
    goto error;
  }
error:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Invalid ELF");

    gum_elf_module_unload (self);

    return FALSE;
  }
}

static void
gum_elf_module_unload (GumElfModule * self)
{
  self->dynamic_strings = NULL;

  self->dynamic_address_state = GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;
  self->preferred_address = 0;

  self->ehdr = NULL;

  g_clear_pointer (&self->elf, elf_end);

  switch (self->source)
  {
    case GUM_ELF_SOURCE_NONE:
      break;
    case GUM_ELF_SOURCE_FILE:
      munmap (self->file_data, self->file_size);
      self->file_data = NULL;
      self->file_size = 0;
      break;
    case GUM_ELF_SOURCE_BLOB:
      g_free (self->file_data);
      self->file_data = NULL;
      self->file_size = 0;
      break;
    case GUM_ELF_SOURCE_VDSO:
      break;
  }
  self->source = GUM_ELF_SOURCE_NONE;
}

const gchar *
gum_elf_module_get_name (GumElfModule * self)
{
  return self->name;
}

const gchar *
gum_elf_module_get_path (GumElfModule * self)
{
  return self->path;
}

GumAddress
gum_elf_module_get_base_address (GumElfModule * self)
{
  return self->base_address;
}

GumAddress
gum_elf_module_get_preferred_address (GumElfModule * self)
{
  return self->preferred_address;
}

GumAddress
gum_elf_module_get_entrypoint (GumElfModule * self)
{
  GumAddress entrypoint = self->ehdr->e_entry;

  if (self->ehdr->e_type == ET_DYN)
    entrypoint += self->base_address;

  return gum_elf_module_translate_to_online (self, entrypoint);
}

gpointer
gum_elf_module_get_elf (GumElfModule * self)
{
  return self->elf;
}

gconstpointer
gum_elf_module_get_file_data (GumElfModule * self)
{
  return self->file_data;
}

gboolean
gum_elf_module_has_interp (GumElfModule * self)
{
  GElf_Half header_count, header_index;

  header_count = self->ehdr->e_phnum;
  for (header_index = 0; header_index != header_count; header_index++)
  {
    GElf_Phdr phdr;

    gelf_getphdr (self->elf, header_index, &phdr);

    if (phdr.p_type == PT_INTERP)
      return TRUE;
  }

  return FALSE;
}

void
gum_elf_module_enumerate_dependencies (GumElfModule * self,
                                       GumFoundElfDependencyFunc func,
                                       gpointer user_data)
{
  GumElfEnumerateDepsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.module = self;

  gum_elf_module_enumerate_dynamic_entries (self, gum_emit_each_needed, &ctx);
}

static gboolean
gum_emit_each_needed (const GumElfDynamicEntryDetails * details,
                      gpointer user_data)
{
  GumElfEnumerateDepsContext * ctx = user_data;
  GumElfDependencyDetails d;

  if (details->tag != GUM_ELF_DYNAMIC_NEEDED)
    return TRUE;

  d.name = ctx->module->dynamic_strings + details->val;

  return ctx->func (&d, ctx->user_data);
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
    d.slot = 0; /* TODO */

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

#ifdef HAVE_ANDROID
  if (gum_android_is_linker_module_name (self->path))
  {
    const gchar ** magic_exports;
    guint i;

    magic_exports = gum_android_get_magic_linker_export_names ();

    for (i = 0; magic_exports[i] != NULL; i++)
    {
      const gchar * name = magic_exports[i];
      GumExportDetails d;

      d.type = GUM_EXPORT_FUNCTION;
      d.name = name;
      d.address = gum_module_find_export_by_name (self->path, name);
      g_assert (d.address != 0);

      if (!func (&d, user_data))
        return;
    }
  }
#endif

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
                                          GumFoundElfSymbolFunc func,
                                          gpointer user_data)
{
  GumElfStoreSymtabParamsContext ctx;
  gsize entry_index;
  const guint8 elf_class = self->ehdr->e_ident[EI_CLASS];
  const gchar * dynamic_strings = self->dynamic_strings;

  ctx.pending = 3;
  ctx.found_hash = FALSE;

  ctx.entries = NULL;
  ctx.entry_size = 0;
  ctx.entry_count = 0;

  ctx.module = self;

  gum_elf_module_enumerate_dynamic_entries (self, gum_store_symtab_params,
      &ctx);
  if (ctx.pending != 0)
    return;

  gum_elf_module_enumerate_sections (self, gum_adjust_symtab_params, &ctx);

  for (entry_index = 1; entry_index != ctx.entry_count; entry_index++)
  {
    gpointer entry = ctx.entries + (entry_index * ctx.entry_size);
    GumElfSymbolDetails details;
    GumAddress raw_address;

    if (elf_class == ELFCLASS32)
    {
      Elf32_Sym * sym = entry;

      details.name = dynamic_strings + sym->st_name;
      details.size = sym->st_size;
      details.type = GELF_ST_TYPE (sym->st_info);
      details.bind = GELF_ST_BIND (sym->st_info);
      details.section_header_index = sym->st_shndx;

      raw_address = sym->st_value;
    }
    else
    {
      Elf64_Sym * sym = entry;

      details.name = dynamic_strings + sym->st_name;
      details.size = sym->st_size;
      details.type = GELF_ST_TYPE (sym->st_info);
      details.bind = GELF_ST_BIND (sym->st_info);
      details.section_header_index = sym->st_shndx;

      raw_address = sym->st_value;
    }

    details.address = (raw_address != 0)
        ? gum_elf_module_translate_to_online (self, raw_address)
        : 0;

    if (!func (&details, user_data))
      return;
  }
}

static gboolean
gum_store_symtab_params (const GumElfDynamicEntryDetails * details,
                         gpointer user_data)
{
  GumElfStoreSymtabParamsContext * ctx = user_data;

  switch (details->tag)
  {
    case GUM_ELF_DYNAMIC_SYMTAB:
      ctx->entries = gum_elf_module_resolve_dynamic_virtual_location (
          ctx->module, details->val);
      ctx->pending--;
      break;
    case GUM_ELF_DYNAMIC_SYMENT:
      ctx->entry_size = details->val;
      ctx->pending--;
      break;
    case GUM_ELF_DYNAMIC_HASH:
    {
      const guint32 * hash_params;
      guint32 nchain;

      if (ctx->found_hash)
        break;
      ctx->found_hash = TRUE;

      hash_params = gum_elf_module_resolve_dynamic_virtual_location (
          ctx->module, details->val);
      nchain = hash_params[1];

      ctx->entry_count = nchain;
      ctx->pending--;

      break;
    }
    case GUM_ELF_DYNAMIC_GNU_HASH:
    {
      const guint32 * hash_params;
      guint32 nbuckets;
      guint32 symoffset;
      guint32 bloom_size;
      const gsize * bloom;
      const guint32 * buckets;
      const guint32 * chain;
      guint32 highest_index, bucket_index;

      if (ctx->found_hash)
        break;
      ctx->found_hash = TRUE;

      hash_params = gum_elf_module_resolve_dynamic_virtual_location (
          ctx->module, details->val);
      nbuckets = hash_params[0];
      symoffset = hash_params[1];
      bloom_size = hash_params[2];
      bloom = (gsize *) (hash_params + 4);
      buckets = (const guint32 *) (bloom + bloom_size);
      chain = buckets + nbuckets;

      highest_index = 0;
      for (bucket_index = 0; bucket_index != nbuckets; bucket_index++)
      {
        highest_index = MAX (buckets[bucket_index], highest_index);
      }

      if (highest_index >= symoffset)
      {
        while (TRUE)
        {
          guint32 hash = chain[highest_index - symoffset];

          if ((hash & 1) != 0)
            break;

          highest_index++;
        }
      }

      ctx->entry_count = highest_index + 1;
      ctx->pending--;

      break;
    }
    default:
      break;
  }

  return ctx->pending != 0;
}

static gboolean
gum_adjust_symtab_params (const GumElfSectionDetails * details,
                          gpointer user_data)
{
  GumElfStoreSymtabParamsContext * ctx = user_data;

  if (details->address == GUM_ADDRESS (ctx->entries))
  {
    ctx->entry_count = details->size / ctx->entry_size;
    return FALSE;
  }

  return TRUE;
}

void
gum_elf_module_enumerate_symbols (GumElfModule * self,
                                  GumFoundElfSymbolFunc func,
                                  gpointer user_data)
{
  gum_elf_module_enumerate_symbols_in_section (self, SHT_SYMTAB, func,
      user_data);
}

static void
gum_elf_module_enumerate_symbols_in_section (GumElfModule * self,
                                             GumElfSectionHeaderType section,
                                             GumFoundElfSymbolFunc func,
                                             gpointer user_data)
{
  Elf_Scn * scn;
  GElf_Shdr shdr;
  gboolean carry_on;
  GElf_Word symbol_count, symbol_index;
  Elf_Data * data;

  if (!gum_elf_module_find_section_header_by_type (self, section, &scn, &shdr))
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
    details.address = (sym.st_value != 0)
        ? gum_elf_module_translate_to_online (self, sym.st_value)
        : 0;
    details.size = sym.st_size;
    details.type = GELF_ST_TYPE (sym.st_info);
    details.bind = GELF_ST_BIND (sym.st_info);
    details.section_header_index = sym.st_shndx;

    carry_on = func (&details, user_data);
  }
}

void
gum_elf_module_enumerate_dynamic_entries (GumElfModule * self,
                                          GumFoundElfDynamicEntryFunc func,
                                          gpointer user_data)
{
  GElf_Phdr phdr;
  gpointer dynamic_start;
  gsize dynamic_size;

  if (!gum_elf_module_find_dynamic_phdr (self, &phdr))
    return;

  if (self->mode == GUM_ELF_MODE_ONLINE)
  {
    dynamic_start = GSIZE_TO_POINTER (
        gum_elf_module_translate_to_online (self, phdr.p_vaddr));
    dynamic_size = phdr.p_memsz;
  }
  else
  {
    dynamic_start = (guint8 *) self->file_data + phdr.p_offset;
    dynamic_size = phdr.p_filesz;
  }

  if (self->ehdr->e_ident[EI_CLASS] == ELFCLASS32)
  {
    Elf32_Dyn * entries;
    guint entry_count, entry_index;

    entries = dynamic_start;
    entry_count = dynamic_size / sizeof (Elf32_Dyn);

    for (entry_index = 0; entry_index != entry_count; entry_index++)
    {
      Elf32_Dyn * entry = &entries[entry_index];
      GumElfDynamicEntryDetails d;

      d.tag = entry->d_tag;
      d.val = entry->d_un.d_val;

      if (!func (&d, user_data))
        return;
    }
  }
  else
  {
    Elf64_Dyn * entries;
    guint entry_count, entry_index;

    entries = dynamic_start;
    entry_count = dynamic_size / sizeof (Elf64_Dyn);

    for (entry_index = 0; entry_index != entry_count; entry_index++)
    {
      Elf64_Dyn * entry = &entries[entry_index];
      GumElfDynamicEntryDetails d;

      d.tag = entry->d_tag;
      d.val = entry->d_un.d_val;

      if (!func (&d, user_data))
        return;
    }
  }
}

static gboolean
gum_elf_module_find_address_file_offset (GumElfModule * self,
                                         GumAddress address,
                                         guint64 * offset)
{
  GElf_Phdr phdr;
  gsize delta;

  if (!gum_elf_module_find_load_phdr_by_address (self, address, &phdr))
    return FALSE;

  delta = address - phdr.p_vaddr;
  if (delta >= phdr.p_filesz)
    return FALSE;

  *offset = delta;

  return TRUE;
}

static gboolean
gum_elf_module_find_address_protection (GumElfModule * self,
                                        GumAddress address,
                                        GumPageProtection * prot)
{
  GElf_Phdr phdr;
  GumPageProtection p;

  if (!gum_elf_module_find_load_phdr_by_address (self, address, &phdr))
    return FALSE;

  p = GUM_PAGE_NO_ACCESS;
  if ((phdr.p_flags & PF_R) != 0)
    p |= GUM_PAGE_READ;
  if ((phdr.p_flags & PF_W) != 0)
    p |= GUM_PAGE_WRITE;
  if ((phdr.p_flags & PF_X) != 0)
    p |= GUM_PAGE_EXECUTE;

  *prot = p;

  return TRUE;
}

static gboolean
gum_elf_module_find_load_phdr_by_address (GumElfModule * self,
                                          GumAddress address,
                                          GElf_Phdr * phdr)
{
  GElf_Half header_count, header_index;

  header_count = self->ehdr->e_phnum;
  for (header_index = 0; header_index != header_count; header_index++)
  {
    gelf_getphdr (self->elf, header_index, phdr);

    if (phdr->p_type == PT_LOAD &&
        address >= phdr->p_vaddr &&
        address < phdr->p_vaddr + phdr->p_memsz)
    {
      return TRUE;
    }
  }

  return FALSE;
}

static gboolean
gum_elf_module_find_dynamic_phdr (GumElfModule * self,
                                  GElf_Phdr * phdr)
{
  GElf_Half header_count, header_index;

  header_count = self->ehdr->e_phnum;
  for (header_index = 0; header_index != header_count; header_index++)
  {
    gelf_getphdr (self->elf, header_index, phdr);

    if (phdr->p_type == PT_DYNAMIC)
      return TRUE;
  }

  return FALSE;
}

void
gum_elf_module_enumerate_sections (GumElfModule * self,
                                   GumFoundElfSectionFunc func,
                                   gpointer user_data)
{
  Elf_Scn * strings_scn;
  GElf_Shdr strings_shdr;
  const gchar * strings;
  Elf_Scn * cur;

  if (!gum_elf_module_find_section_header_by_index (self,
      self->ehdr->e_shstrndx, &strings_scn, &strings_shdr))
    return;

  strings = self->file_data + strings_shdr.sh_offset;

  cur = NULL;
  while ((cur = elf_nextscn (self->elf, cur)) != NULL)
  {
    GElf_Shdr shdr;
    GumElfSectionDetails d;

    gelf_getshdr (cur, &shdr);

    d.name = strings + shdr.sh_name;
    d.type = shdr.sh_type;
    d.flags = shdr.sh_flags;
    d.address = gum_elf_module_translate_to_online (self, shdr.sh_addr);
    d.offset = shdr.sh_offset;
    d.size = shdr.sh_size;
    d.link = shdr.sh_link;
    d.info = shdr.sh_info;
    d.alignment = shdr.sh_addralign;
    d.entry_size = shdr.sh_entsize;
    if (!gum_elf_module_find_address_protection (self, shdr.sh_addr,
        &d.protection))
    {
      d.protection = GUM_PAGE_NO_ACCESS;
    }

    if (!func (&d, user_data))
      return;
  }
}

static gboolean
gum_elf_module_find_section_header_by_index (GumElfModule * self,
                                             guint index,
                                             Elf_Scn ** scn,
                                             GElf_Shdr * shdr)
{
  guint current_index;
  Elf_Scn * current_section;

  current_index = 1;
  current_section = NULL;

  while ((current_section = elf_nextscn (self->elf, current_section)) != NULL)
  {
    if (current_index == index)
    {
      gelf_getshdr (current_section, shdr);

      *scn = current_section;
      return TRUE;
    }

    current_index++;
  }

  return FALSE;
}

static gboolean
gum_elf_module_find_section_header_by_type (GumElfModule * self,
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

    if (phdr.p_type == PT_LOAD && phdr.p_offset == 0)
      return phdr.p_vaddr;
  }

  return 0;
}

static GumElfDynamicAddressState
gum_elf_module_detect_dynamic_address_state (GumElfModule * self)
{
  /* FIXME: this is not very generic */

  if (self->source == GUM_ELF_SOURCE_VDSO)
    return GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;

#if defined (HAVE_ANDROID) || defined (HAVE_FREEBSD)
  return GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;
#elif defined (HAVE_MIPS)
  /*
   * This value was set for MIPS based upon experimentation. However,
   * this may be influenced by platform configuration or other factors.
   */
  return GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;
#else
  return GUM_ELF_DYNAMIC_ADDRESS_ADJUSTED;
#endif
}

GumAddress
gum_elf_module_translate_to_offline (GumElfModule * self,
                                     GumAddress online_address)
{
  return self->preferred_address + (online_address - self->base_address);
}

GumAddress
gum_elf_module_translate_to_online (GumElfModule * self,
                                    GumAddress offline_address)
{
  return self->base_address + (offline_address - self->preferred_address);
}

static gpointer
gum_elf_module_resolve_dynamic_virtual_location (GumElfModule * self,
                                                 GumAddress address)
{
  if (self->mode == GUM_ELF_MODE_ONLINE)
  {
    switch (self->dynamic_address_state)
    {
      case GUM_ELF_DYNAMIC_ADDRESS_PRISTINE:
        return GSIZE_TO_POINTER (
            gum_elf_module_translate_to_online (self, address));
      case GUM_ELF_DYNAMIC_ADDRESS_ADJUSTED:
        return GSIZE_TO_POINTER (address);
      default:
        g_assert_not_reached ();
    }

    return NULL;
  }
  else
  {
    guint64 offset;

    if (!gum_elf_module_find_address_file_offset (self, address, &offset))
      return NULL;

    return (guint8 *) self->file_data + offset;
  }
}

static gboolean
gum_store_dynamic_string_table (const GumElfDynamicEntryDetails * details,
                                gpointer user_data)
{
  GumElfModule * self = user_data;

  if (details->tag != GUM_ELF_DYNAMIC_STRTAB)
    return TRUE;

  self->dynamic_strings = gum_elf_module_resolve_dynamic_virtual_location (self,
      details->val);
  return FALSE;
}

static gboolean
gum_maybe_extract_from_apk (const gchar * path,
                            gpointer * file_data,
                            gsize * file_size)
{
#if defined (HAVE_ANDROID) && defined (HAVE_MINIZIP)
  gboolean success = FALSE;
  gchar ** tokens;
  const gchar * apk_path, * file_path, * bare_file_path;
  void * zip_stream = NULL;
  void * zip_reader = NULL;
  gsize size;
  gpointer buffer = NULL;

  tokens = g_strsplit (path, "!", 2);
  if (g_strv_length (tokens) != 2 || !g_str_has_suffix (tokens[0], ".apk"))
    goto beach;
  apk_path = tokens[0];
  file_path = tokens[1];
  bare_file_path = file_path + 1;

  mz_stream_os_create (&zip_stream);
  if (mz_stream_os_open (zip_stream, apk_path, MZ_OPEN_MODE_READ) != MZ_OK)
    goto beach;

  mz_zip_reader_create (&zip_reader);
  if (mz_zip_reader_open (zip_reader, zip_stream) != MZ_OK)
    goto beach;

  if (mz_zip_reader_locate_entry (zip_reader, bare_file_path, TRUE) != MZ_OK)
    goto beach;

  size = mz_zip_reader_entry_save_buffer_length (zip_reader);
  buffer = g_malloc (size);
  if (mz_zip_reader_entry_save_buffer (zip_reader, buffer, size) != MZ_OK)
    goto beach;

  success = TRUE;

  *file_data = g_steal_pointer (&buffer);
  *file_size = size;

beach:
  g_free (buffer);
  mz_zip_reader_delete (&zip_reader);
  mz_stream_os_delete (&zip_stream);
  g_strfreev (tokens);

  return success;
#else
  return FALSE;
#endif
}

#endif
