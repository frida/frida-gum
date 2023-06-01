/*
 * Copyright (C) 2010-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2019 Jon Wilson <jonwilson@zepler.net>
 * Copyright (C)      2021 Paul Schmidt <p.schmidt@tu-bs.de>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumelfmodule.h"

#include "gumelfmodule-priv.h"
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

#define GUM_ELF_DEFAULT_MAPPED_SIZE (64 * 1024)
#define GUM_ELF_PAGE_START(value, page_size) \
    (GUM_ADDRESS (value) & ~GUM_ADDRESS (page_size - 1))

#define GUM_CHECK_BOUNDS(l, r, name) \
    G_STMT_START \
    { \
      if (!gum_elf_module_check_bounds (self, l, r, data, size, name, error)) \
        goto propagate_error; \
    } \
    G_STMT_END
#define GUM_CHECK_STR_BOUNDS(s, name) \
    G_STMT_START \
    { \
      if (!gum_elf_module_check_str_bounds (self, s, data, size, name, error)) \
        goto propagate_error; \
    } \
    G_STMT_END
#define GUM_READ(dst, src, type) \
    dst = G_PASTE (gum_elf_module_read_, type) (self, &src);

typedef guint GumElfDynamicAddressState;
typedef struct _GumElfEnumerateDepsContext GumElfEnumerateDepsContext;
typedef struct _GumElfEnumerateImportsContext GumElfEnumerateImportsContext;
typedef struct _GumElfEnumerateExportsContext GumElfEnumerateExportsContext;
typedef struct _GumElfStoreSymtabParamsContext GumElfStoreSymtabParamsContext;

enum
{
  PROP_0,
  PROP_ETYPE,
  PROP_POINTER_SIZE,
  PROP_BYTE_ORDER,
  PROP_OS_ABI,
  PROP_OS_ABI_VERSION,
  PROP_MACHINE,
  PROP_BASE_ADDRESS,
  PROP_PREFERRED_ADDRESS,
  PROP_MAPPED_SIZE,
  PROP_ENTRYPOINT,
  PROP_INTERPRETER,
  PROP_SOURCE_PATH,
  PROP_SOURCE_BLOB,
  PROP_SOURCE_MODE,
};

struct _GumElfModule
{
  GObject parent;

  gchar * source_path;
  GBytes * source_blob;
  GumElfSourceMode source_mode;

  GBytes * file_bytes;
  gconstpointer file_data;
  gsize file_size;

  GumElfEhdr ehdr;
  GArray * phdrs;
  GArray * shdrs;
  GArray * dyns;

  GArray * sections;

  GumAddress base_address;
  GumAddress preferred_address;
  guint64 mapped_size;
  GumElfDynamicAddressState dynamic_address_state;
  const gchar * dynamic_strings;
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

static void gum_elf_module_finalize (GObject * object);
static void gum_elf_module_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_elf_module_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gboolean gum_elf_module_load_elf_header (GumElfModule * self,
    GError ** error);
static gboolean gum_elf_module_load_program_headers (GumElfModule * self,
    GError ** error);
static gboolean gum_elf_module_load_section_headers (GumElfModule * self,
    GError ** error);
static gboolean gum_elf_module_load_section_details (GumElfModule * self,
    GError ** error);
static void gum_elf_section_details_clear (GumElfSectionDetails * d);
static gboolean gum_elf_module_load_dynamic_entries (GumElfModule * self,
    GError ** error);
static gconstpointer gum_elf_module_get_live_data (GumElfModule * self,
    gsize * size);
static void gum_elf_module_unload (GumElfModule * self);
static gboolean gum_emit_each_needed (const GumElfDynamicEntryDetails * details,
    gpointer user_data);
static gboolean gum_emit_elf_import (const GumElfSymbolDetails * details,
    gpointer user_data);
static gboolean gum_emit_elf_export (const GumElfSymbolDetails * details,
    gpointer user_data);
static void gum_elf_module_parse_symbol (GumElfModule * self,
    const GumElfSym * sym, const gchar * strings, GumElfSymbolDetails * d);
static void gum_elf_module_read_symbol (GumElfModule * self,
    gconstpointer raw_sym, GumElfSym * sym);
static gboolean gum_store_symtab_params (
    const GumElfDynamicEntryDetails * details, gpointer user_data);
static gboolean gum_adjust_symtab_params (const GumElfSectionDetails * details,
    gpointer user_data);
static void gum_elf_module_enumerate_symbols_in_section (GumElfModule * self,
    GumElfSectionType section, GumFoundElfSymbolFunc func, gpointer user_data);
static gboolean gum_elf_module_find_address_protection (GumElfModule * self,
    GumAddress address, GumPageProtection * prot);
static GumPageProtection gum_parse_phdr_protection (const GumElfPhdr * phdr);
static const GumElfPhdr * gum_elf_module_find_phdr_by_type (GumElfModule * self,
    guint32 type);
static const GumElfPhdr * gum_elf_module_find_load_phdr_by_address (
    GumElfModule * self, GumAddress address);
static const GumElfShdr * gum_elf_module_find_section_header_by_index (
    GumElfModule * self, guint i);
static const GumElfShdr * gum_elf_module_find_section_header_by_type (
    GumElfModule * self, GumElfSectionType type);
static const GumElfSectionDetails *
    gum_elf_module_find_section_details_by_index (GumElfModule * self, guint i);
static GumAddress gum_elf_module_compute_preferred_address (
    GumElfModule * self);
static guint64 gum_elf_module_compute_mapped_size (GumElfModule * self);
static GumElfDynamicAddressState gum_elf_module_detect_dynamic_address_state (
    GumElfModule * self);
static gpointer gum_elf_module_resolve_dynamic_virtual_location (
    GumElfModule * self, GumAddress address);
static gboolean gum_store_dynamic_string_table (
    const GumElfDynamicEntryDetails * details, gpointer user_data);

static gboolean gum_elf_module_check_bounds (GumElfModule * self,
    gconstpointer left, gconstpointer right, gconstpointer base, gsize size,
    const gchar * name, GError ** error);
static gboolean gum_elf_module_check_str_bounds (GumElfModule * self,
    const gchar * str, gconstpointer base, gsize size, const gchar * name,
    GError ** error);

static guint8 gum_elf_module_read_uint8 (GumElfModule * self, const guint8 * v);
static guint16 gum_elf_module_read_uint16 (GumElfModule * self,
    const guint16 * v);
static gint32 gum_elf_module_read_int32 (GumElfModule * self, const gint32 * v);
static guint32 gum_elf_module_read_uint32 (GumElfModule * self,
    const guint32 * v);
static gint64 gum_elf_module_read_int64 (GumElfModule * self, const gint64 * v);
static guint64 gum_elf_module_read_uint64 (GumElfModule * self,
    const guint64 * v);

static gboolean gum_maybe_extract_from_apk (const gchar * path,
    GBytes ** file_bytes);

G_DEFINE_TYPE (GumElfModule, gum_elf_module, G_TYPE_OBJECT)

static void
gum_elf_module_class_init (GumElfModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_elf_module_finalize;
  object_class->get_property = gum_elf_module_get_property;
  object_class->set_property = gum_elf_module_set_property;

  g_object_class_install_property (object_class, PROP_ETYPE,
      g_param_spec_enum ("etype", "Type", "ELF Type",
      GUM_TYPE_ELF_TYPE, GUM_ELF_NONE,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_POINTER_SIZE,
      g_param_spec_uint ("pointer-size", "Pointer Size",
      "Pointer size in bytes", 4, 8, 8,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BYTE_ORDER,
      g_param_spec_int ("byte-order", "Byte Order",
      "Byte order/endian", G_LITTLE_ENDIAN, G_BIG_ENDIAN, G_BYTE_ORDER,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_OS_ABI,
      g_param_spec_enum ("os-abi", "OS ABI", "Operating system ABI",
      GUM_TYPE_ELF_OSABI, GUM_ELF_OS_SYSV,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_OS_ABI_VERSION,
      g_param_spec_uint ("os-abi-version", "OS ABI Version",
      "Operating system ABI version", 0, G_MAXUINT8, 0,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_MACHINE,
      g_param_spec_enum ("machine", "Machine", "Machine",
      GUM_TYPE_ELF_MACHINE, GUM_ELF_MACHINE_NONE,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BASE_ADDRESS,
      g_param_spec_uint64 ("base-address", "Base Address",
      "Base virtual address, or zero when operating offline", 0,
      G_MAXUINT64, 0,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PREFERRED_ADDRESS,
      g_param_spec_uint64 ("preferred-address", "Preferred Address",
      "Preferred virtual address", 0, G_MAXUINT64, 0,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_MAPPED_SIZE,
      g_param_spec_uint64 ("mapped-size", "Mapped Size",
      "Mapped size", 0, G_MAXUINT64, GUM_ELF_DEFAULT_MAPPED_SIZE,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_ENTRYPOINT,
      g_param_spec_uint64 ("entrypoint", "Entrypoint",
      "Entrypoint virtual address", 0, G_MAXUINT64, 0,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_INTERPRETER,
      g_param_spec_string ("interpreter", "Interpreter", "Interpreter", NULL,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_PATH,
      g_param_spec_string ("source-path", "SourcePath", "Source path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_BLOB,
      g_param_spec_boxed ("source-blob", "SourceBlob", "Source blob",
      G_TYPE_BYTES,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_MODE,
      g_param_spec_enum ("source-mode", "SourceMode", "Source mode",
      GUM_TYPE_ELF_SOURCE_MODE, GUM_ELF_SOURCE_MODE_OFFLINE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

static void
gum_elf_module_init (GumElfModule * self)
{
  self->phdrs = g_array_new (FALSE, FALSE, sizeof (GumElfPhdr));
  self->shdrs = g_array_new (FALSE, FALSE, sizeof (GumElfShdr));
  self->dyns = g_array_new (FALSE, FALSE, sizeof (GumElfDyn));

  self->sections = g_array_new (FALSE, TRUE, sizeof (GumElfSectionDetails));
  g_array_set_clear_func (self->sections,
      (GDestroyNotify) gum_elf_section_details_clear);

  self->mapped_size = GUM_ELF_DEFAULT_MAPPED_SIZE;
}

static void
gum_elf_module_finalize (GObject * object)
{
  GumElfModule * self = GUM_ELF_MODULE (object);

  gum_elf_module_unload (self);

  g_array_unref (self->sections);

  g_array_unref (self->dyns);
  g_array_unref (self->shdrs);
  g_array_unref (self->phdrs);

  g_bytes_unref (self->source_blob);
  g_free (self->source_path);

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
    case PROP_ETYPE:
      g_value_set_enum (value, gum_elf_module_get_etype (self));
      break;
    case PROP_POINTER_SIZE:
      g_value_set_uint (value, gum_elf_module_get_pointer_size (self));
      break;
    case PROP_BYTE_ORDER:
      g_value_set_int (value, gum_elf_module_get_byte_order (self));
      break;
    case PROP_OS_ABI:
      g_value_set_enum (value, gum_elf_module_get_os_abi (self));
      break;
    case PROP_OS_ABI_VERSION:
      g_value_set_uint (value, gum_elf_module_get_os_abi_version (self));
      break;
    case PROP_MACHINE:
      g_value_set_enum (value, gum_elf_module_get_machine (self));
      break;
    case PROP_BASE_ADDRESS:
      g_value_set_uint64 (value, gum_elf_module_get_base_address (self));
      break;
    case PROP_PREFERRED_ADDRESS:
      g_value_set_uint64 (value, gum_elf_module_get_preferred_address (self));
      break;
    case PROP_MAPPED_SIZE:
      g_value_set_uint64 (value, gum_elf_module_get_mapped_size (self));
      break;
    case PROP_ENTRYPOINT:
      g_value_set_uint64 (value, gum_elf_module_get_entrypoint (self));
      break;
    case PROP_INTERPRETER:
      g_value_set_string (value, gum_elf_module_get_interpreter (self));
      break;
    case PROP_SOURCE_PATH:
      g_value_set_string (value, gum_elf_module_get_source_path (self));
      break;
    case PROP_SOURCE_BLOB:
      g_value_set_boxed (value, gum_elf_module_get_source_blob (self));
      break;
    case PROP_SOURCE_MODE:
      g_value_set_enum (value, gum_elf_module_get_source_mode (self));
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
    case PROP_BASE_ADDRESS:
      self->base_address = g_value_get_uint64 (value);
      break;
    case PROP_SOURCE_PATH:
      g_free (self->source_path);
      self->source_path = g_value_dup_string (value);
      break;
    case PROP_SOURCE_BLOB:
      g_bytes_unref (self->source_blob);
      self->source_blob = g_value_dup_boxed (value);
      break;
    case PROP_SOURCE_MODE:
      self->source_mode = g_value_get_enum (value);
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
      "source-path", path,
      "source-mode", GUM_ELF_SOURCE_MODE_OFFLINE,
      NULL);
  if (!gum_elf_module_load (module, error))
  {
    g_object_unref (module);
    return NULL;
  }

  return module;
}

GumElfModule *
gum_elf_module_new_from_blob (GBytes * blob,
                              GError ** error)
{
  GumElfModule * module;

  module = g_object_new (GUM_ELF_TYPE_MODULE,
      "source-blob", blob,
      "source-mode", GUM_ELF_SOURCE_MODE_OFFLINE,
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
      "base-address", base_address,
      "source-path", path,
      "source-mode", GUM_ELF_SOURCE_MODE_ONLINE,
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
  GError * local_error = NULL;

  if (self->file_bytes != NULL)
    return TRUE;

  if (self->source_blob != NULL)
  {
    self->file_bytes = g_bytes_ref (self->source_blob);
  }
  else
  {
#ifdef HAVE_LINUX
    if (self->source_mode == GUM_ELF_SOURCE_MODE_ONLINE &&
        strcmp (self->source_path, "linux-vdso.so.1") == 0)
    {
      self->file_bytes = g_bytes_new_static (
          GSIZE_TO_POINTER (self->base_address), gum_query_page_size ());
    }
    else
#endif
    if (!gum_maybe_extract_from_apk (self->source_path, &self->file_bytes))
    {
      GMappedFile * file =
          g_mapped_file_new (self->source_path, FALSE, &local_error);
      if (file == NULL)
        goto unable_to_open;
      self->file_bytes = g_mapped_file_get_bytes (file);
      g_mapped_file_unref (file);
    }
  }

  self->file_data = g_bytes_get_data (self->file_bytes, &self->file_size);

  if (!gum_elf_module_load_elf_header (self, error))
    goto propagate_error;

  if (!gum_elf_module_load_program_headers (self, error))
    goto propagate_error;

  self->mapped_size = gum_elf_module_compute_mapped_size (self);
  self->preferred_address = gum_elf_module_compute_preferred_address (self);

  if (!gum_elf_module_load_section_headers (self, error))
    goto propagate_error;

  if (!gum_elf_module_load_dynamic_entries (self, error))
    goto propagate_error;

  self->dynamic_address_state =
      gum_elf_module_detect_dynamic_address_state (self);

  gum_elf_module_enumerate_dynamic_entries (self,
      gum_store_dynamic_string_table, self);

  if (!gum_elf_module_load_section_details (self, error))
    goto propagate_error;

  return TRUE;

unable_to_open:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "%s", local_error->message);
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_error (&local_error);

    gum_elf_module_unload (self);

    return FALSE;
  }
}

static gboolean
gum_elf_module_load_elf_header (GumElfModule * self,
                                GError ** error)
{
  gconstpointer data;
  gsize size;
  const GumElfIdentity * identity;

  data = gum_elf_module_get_live_data (self, &size);

  identity = data;
  GUM_CHECK_BOUNDS (identity, identity + 1, "ELF header");
  self->ehdr.identity = *identity;

#define GUM_READ_EHDR_FIELD(name, type) \
    GUM_READ (self->ehdr.name, src->name, type)
#define GUM_READ_EHDR() \
    G_STMT_START \
    { \
      GUM_READ_EHDR_FIELD (type,      uint16); \
      GUM_READ_EHDR_FIELD (machine,   uint16); \
      GUM_READ_EHDR_FIELD (version,   uint32); \
      GUM_READ_EHDR_FIELD (entry,     uint64); \
      GUM_READ_EHDR_FIELD (phoff,     uint64); \
      GUM_READ_EHDR_FIELD (shoff,     uint64); \
      GUM_READ_EHDR_FIELD (flags,     uint32); \
      GUM_READ_EHDR_FIELD (ehsize,    uint16); \
      GUM_READ_EHDR_FIELD (phentsize, uint16); \
      GUM_READ_EHDR_FIELD (phnum,     uint16); \
      GUM_READ_EHDR_FIELD (shentsize, uint16); \
      GUM_READ_EHDR_FIELD (shnum,     uint16); \
      GUM_READ_EHDR_FIELD (shstrndx,  uint16); \
    } \
    G_STMT_END
#define GUM_READ_EHDR32() \
    G_STMT_START \
    { \
      GUM_READ_EHDR_FIELD (type,      uint16); \
      GUM_READ_EHDR_FIELD (machine,   uint16); \
      GUM_READ_EHDR_FIELD (version,   uint32); \
      GUM_READ_EHDR_FIELD (entry,     uint32); \
      GUM_READ_EHDR_FIELD (phoff,     uint32); \
      GUM_READ_EHDR_FIELD (shoff,     uint32); \
      GUM_READ_EHDR_FIELD (flags,     uint32); \
      GUM_READ_EHDR_FIELD (ehsize,    uint16); \
      GUM_READ_EHDR_FIELD (phentsize, uint16); \
      GUM_READ_EHDR_FIELD (phnum,     uint16); \
      GUM_READ_EHDR_FIELD (shentsize, uint16); \
      GUM_READ_EHDR_FIELD (shnum,     uint16); \
      GUM_READ_EHDR_FIELD (shstrndx,  uint16); \
    } \
    G_STMT_END

  switch (identity->klass)
  {
    case GUM_ELF_CLASS_64:
    {
      const GumElfEhdr * src = data;

      GUM_CHECK_BOUNDS (src, src + 1, "ELF header");
      GUM_READ_EHDR ();

      break;
    }
    case GUM_ELF_CLASS_32:
    {
      const GumElfEhdr32 * src = data;

      GUM_CHECK_BOUNDS (src, src + 1, "ELF header");
      GUM_READ_EHDR32 ();

      break;
    }
    default:
      goto invalid_value;
  }

#undef GUM_READ_EHDR_FIELD
#undef GUM_READ_EHDR
#undef GUM_READ_EHDR32

  return TRUE;

invalid_value:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Invalid ELF header");
    goto propagate_error;
  }
propagate_error:
  {
    return FALSE;
  }
}

static gboolean
gum_elf_module_load_program_headers (GumElfModule * self,
                                     GError ** error)
{
  gconstpointer data;
  gsize size;
  guint16 n;
  gconstpointer start, end, cursor;
  guint16 i;

  data = gum_elf_module_get_live_data (self, &size);

  n = self->ehdr.phnum;

  start = (const guint8 *) data + self->ehdr.phoff;
  end = (const guint8 *) start + (n * self->ehdr.phentsize);
  GUM_CHECK_BOUNDS (start, end, "program headers");

  g_array_set_size (self->phdrs, n);

  cursor = start;
  for (i = 0; i != n; i++)
  {
    GumElfPhdr * dst = &g_array_index (self->phdrs, GumElfPhdr, i);

#define GUM_READ_PHDR_FIELD(name, type) \
    GUM_READ (dst->name, src->name, type)
#define GUM_READ_PHDR() \
    G_STMT_START \
    { \
      GUM_READ_PHDR_FIELD (type,   uint32); \
      GUM_READ_PHDR_FIELD (flags,  uint32); \
      GUM_READ_PHDR_FIELD (offset, uint64); \
      GUM_READ_PHDR_FIELD (vaddr,  uint64); \
      GUM_READ_PHDR_FIELD (paddr,  uint64); \
      GUM_READ_PHDR_FIELD (filesz, uint64); \
      GUM_READ_PHDR_FIELD (memsz,  uint64); \
      GUM_READ_PHDR_FIELD (align,  uint64); \
    } \
    G_STMT_END
#define GUM_READ_PHDR32() \
    G_STMT_START \
    { \
      GUM_READ_PHDR_FIELD (type,   uint32); \
      GUM_READ_PHDR_FIELD (offset, uint32); \
      GUM_READ_PHDR_FIELD (vaddr,  uint32); \
      GUM_READ_PHDR_FIELD (paddr,  uint32); \
      GUM_READ_PHDR_FIELD (filesz, uint32); \
      GUM_READ_PHDR_FIELD (memsz,  uint32); \
      GUM_READ_PHDR_FIELD (flags,  uint32); \
      GUM_READ_PHDR_FIELD (align,  uint32); \
    } \
    G_STMT_END

    switch (self->ehdr.identity.klass)
    {
      case GUM_ELF_CLASS_64:
      {
        const GumElfPhdr * src = cursor;
        GUM_READ_PHDR ();
        break;
      }
      case GUM_ELF_CLASS_32:
      {
        const GumElfPhdr32 * src = cursor;
        GUM_READ_PHDR32 ();
        break;
      }
      default:
        g_assert_not_reached ();
    }

#undef GUM_READ_PHDR_FIELD
#undef GUM_READ_PHDR
#undef GUM_READ_PHDR32

    cursor = (const guint8 *) cursor + self->ehdr.phentsize;
  }

  return TRUE;

propagate_error:
  {
    return FALSE;
  }
}

static gboolean
gum_elf_module_load_section_headers (GumElfModule * self,
                                     GError ** error)
{
  gconstpointer data;
  gsize size;
  guint16 n;
  gconstpointer start, end, cursor;
  guint16 i;

  data = gum_elf_module_get_file_data (self, &size);

  n = self->ehdr.shnum;

  start = (const guint8 *) data + self->ehdr.shoff;
  end = (const guint8 *) start + (n * self->ehdr.shentsize);
  if (end == start)
    return TRUE;
  GUM_CHECK_BOUNDS (start, end, "section headers");

  g_array_set_size (self->shdrs, n);

  cursor = start;
  for (i = 0; i != n; i++)
  {
    GumElfShdr * dst = &g_array_index (self->shdrs, GumElfShdr, i);

#define GUM_READ_SHDR_FIELD(name, type) \
    GUM_READ (dst->name, src->name, type)
#define GUM_READ_SHDR() \
    G_STMT_START \
    { \
      GUM_READ_SHDR_FIELD (name,      uint32); \
      GUM_READ_SHDR_FIELD (type,      uint32); \
      GUM_READ_SHDR_FIELD (flags,     uint64); \
      GUM_READ_SHDR_FIELD (addr,      uint64); \
      GUM_READ_SHDR_FIELD (offset,    uint64); \
      GUM_READ_SHDR_FIELD (size,      uint64); \
      GUM_READ_SHDR_FIELD (link,      uint32); \
      GUM_READ_SHDR_FIELD (info,      uint32); \
      GUM_READ_SHDR_FIELD (addralign, uint64); \
      GUM_READ_SHDR_FIELD (entsize,   uint64); \
    } \
    G_STMT_END
#define GUM_READ_SHDR32() \
    G_STMT_START \
    { \
      GUM_READ_SHDR_FIELD (name,      uint32); \
      GUM_READ_SHDR_FIELD (type,      uint32); \
      GUM_READ_SHDR_FIELD (flags,     uint32); \
      GUM_READ_SHDR_FIELD (addr,      uint32); \
      GUM_READ_SHDR_FIELD (offset,    uint32); \
      GUM_READ_SHDR_FIELD (size,      uint32); \
      GUM_READ_SHDR_FIELD (link,      uint32); \
      GUM_READ_SHDR_FIELD (info,      uint32); \
      GUM_READ_SHDR_FIELD (addralign, uint32); \
      GUM_READ_SHDR_FIELD (entsize,   uint32); \
    } \
    G_STMT_END

    switch (self->ehdr.identity.klass)
    {
      case GUM_ELF_CLASS_64:
      {
        const GumElfShdr * src = cursor;
        GUM_READ_SHDR ();
        break;
      }
      case GUM_ELF_CLASS_32:
      {
        const GumElfShdr32 * src = cursor;
        GUM_READ_SHDR32 ();
        break;
      }
      default:
        g_assert_not_reached ();
    }

#undef GUM_READ_SHDR_FIELD
#undef GUM_READ_SHDR
#undef GUM_READ_SHDR32

    cursor = (const guint8 *) cursor + self->ehdr.shentsize;
  }

  return TRUE;

propagate_error:
  {
    return FALSE;
  }
}

static gboolean
gum_elf_module_load_section_details (GumElfModule * self,
                                     GError ** error)
{
  const GumElfShdr * strings_shdr;
  gconstpointer data;
  gsize size;
  const gchar * strings;
  guint n, i;

  strings_shdr =
      gum_elf_module_find_section_header_by_index (self, self->ehdr.shstrndx);
  if (strings_shdr == NULL)
    return TRUE;

  data = gum_elf_module_get_file_data (self, &size);

  strings = (const gchar *) data + strings_shdr->offset;

  n = self->shdrs->len;
  g_array_set_size (self->sections, n);

  for (i = 0; i != n; i++)
  {
    const GumElfShdr * shdr =
        &g_array_index (self->shdrs, GumElfShdr, i);
    GumElfSectionDetails * d =
        &g_array_index (self->sections, GumElfSectionDetails, i);
    const gchar * name = strings + shdr->name;

    GUM_CHECK_STR_BOUNDS (name, "section name");

    d->id = g_strdup_printf ("%u%s", 1 + i, name);
    d->name = name;
    d->type = shdr->type;
    d->flags = shdr->flags;
    d->address = gum_elf_module_translate_to_online (self, shdr->addr);
    d->offset = shdr->offset;
    d->size = shdr->size;
    d->link = shdr->link;
    d->info = shdr->info;
    d->alignment = shdr->addralign;
    d->entry_size = shdr->entsize;
    if (!gum_elf_module_find_address_protection (self, shdr->addr,
        &d->protection))
    {
      d->protection = GUM_PAGE_NO_ACCESS;
    }
  }

  return TRUE;

propagate_error:
  {
    g_array_set_size (self->sections, 0);

    return FALSE;
  }
}

static void
gum_elf_section_details_clear (GumElfSectionDetails * d)
{
  g_clear_pointer ((gchar **) &d->id, g_free);
}

static gboolean
gum_elf_module_load_dynamic_entries (GumElfModule * self,
                                     GError ** error)
{
  const GumElfPhdr * phdr;
  gconstpointer data;
  gsize size, entry_size, n;
  gconstpointer start, end, cursor;
  gsize i;

  phdr = gum_elf_module_find_phdr_by_type (self, GUM_ELF_PHDR_DYNAMIC);
  if (phdr == NULL)
    return TRUE;

  data = gum_elf_module_get_live_data (self, &size);

  entry_size = (self->ehdr.identity.klass == GUM_ELF_CLASS_64)
      ? sizeof (GumElfDyn)
      : sizeof (GumElfDyn32);
  n = phdr->filesz / entry_size;

  start = (self->source_mode == GUM_ELF_SOURCE_MODE_ONLINE)
      ? GSIZE_TO_POINTER (
          gum_elf_module_translate_to_online (self, phdr->vaddr))
      : (const guint8 *) data + phdr->offset;
  end = (const guint8 *) start + (n * entry_size);
  GUM_CHECK_BOUNDS (start, end, "dynamic entries");

  g_array_set_size (self->dyns, n);

  cursor = start;
  for (i = 0; i != n; i++)
  {
    GumElfDyn * dst = &g_array_index (self->dyns, GumElfDyn, i);

#define GUM_READ_DYN_FIELD(name, type) \
    GUM_READ (dst->name, src->name, type)
#define GUM_READ_DYN() \
    G_STMT_START \
    { \
      GUM_READ_DYN_FIELD (tag, int64); \
      GUM_READ_DYN_FIELD (val, uint64); \
    } \
    G_STMT_END
#define GUM_READ_DYN32() \
    G_STMT_START \
    { \
      GUM_READ_DYN_FIELD (tag, int32); \
      GUM_READ_DYN_FIELD (val, uint32); \
    } \
    G_STMT_END

    switch (self->ehdr.identity.klass)
    {
      case GUM_ELF_CLASS_64:
      {
        const GumElfDyn * src = cursor;
        GUM_READ_DYN ();
        break;
      }
      case GUM_ELF_CLASS_32:
      {
        const GumElfDyn32 * src = cursor;
        GUM_READ_DYN32 ();
        break;
      }
      default:
        g_assert_not_reached ();
    }

#undef GUM_READ_DYN_FIELD
#undef GUM_READ_DYN
#undef GUM_READ_DYN32

    cursor = (const guint8 *) cursor + entry_size;
  }

  return TRUE;

propagate_error:
  {
    return FALSE;
  }
}

static gconstpointer
gum_elf_module_get_live_data (GumElfModule * self,
                              gsize * size)
{
  if (self->source_mode == GUM_ELF_SOURCE_MODE_ONLINE)
  {
    *size = self->mapped_size;
    return GSIZE_TO_POINTER (self->base_address);
  }
  else
  {
    *size = self->file_size;
    return self->file_data;
  }
}

static void
gum_elf_module_unload (GumElfModule * self)
{
  self->dynamic_strings = NULL;
  self->dynamic_address_state = GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;
  self->mapped_size = GUM_ELF_DEFAULT_MAPPED_SIZE;
  self->preferred_address = 0;

  g_array_set_size (self->sections, 0);

  g_array_set_size (self->dyns, 0);
  g_array_set_size (self->shdrs, 0);
  g_array_set_size (self->phdrs, 0);
  memset (&self->ehdr, 0, sizeof (self->ehdr));

  g_bytes_unref (self->file_bytes);
  self->file_bytes = NULL;
  self->file_data = NULL;
  self->file_size = 0;
}

GumElfType
gum_elf_module_get_etype (GumElfModule * self)
{
  return self->ehdr.type;
}

guint
gum_elf_module_get_pointer_size (GumElfModule * self)
{
  return (self->ehdr.identity.klass == GUM_ELF_CLASS_64) ? 8 : 4;
}

gint
gum_elf_module_get_byte_order (GumElfModule * self)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? G_LITTLE_ENDIAN
      : G_BIG_ENDIAN;
}

GumElfOSABI
gum_elf_module_get_os_abi (GumElfModule * self)
{
  return self->ehdr.identity.os_abi;
}

guint8
gum_elf_module_get_os_abi_version (GumElfModule * self)
{
  return self->ehdr.identity.os_abi_version;
}

GumElfMachine
gum_elf_module_get_machine (GumElfModule * self)
{
  return self->ehdr.machine;
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

guint64
gum_elf_module_get_mapped_size (GumElfModule * self)
{
  return self->mapped_size;
}

GumAddress
gum_elf_module_get_entrypoint (GumElfModule * self)
{
  GumAddress entrypoint = self->ehdr.entry;

  if (self->ehdr.type == GUM_ELF_DYN)
    entrypoint += self->base_address;

  return gum_elf_module_translate_to_online (self, entrypoint);
}

const gchar *
gum_elf_module_get_interpreter (GumElfModule * self)
{
  guint i;

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * phdr = &g_array_index (self->phdrs, GumElfPhdr, i);

    if (phdr->type == GUM_ELF_PHDR_INTERP)
    {
      gconstpointer data;
      gsize size;
      const gchar * interp;

      data = gum_elf_module_get_file_data (self, &size);

      interp = (const gchar *) data + phdr->offset;
      if (!gum_elf_module_check_str_bounds (self, interp, data, size, "interp",
            NULL))
      {
        return NULL;
      }

      return interp;
    }
  }

  return NULL;
}

const gchar *
gum_elf_module_get_source_path (GumElfModule * self)
{
  return self->source_path;
}

GBytes *
gum_elf_module_get_source_blob (GumElfModule * self)
{
  return self->source_blob;
}

GumElfSourceMode
gum_elf_module_get_source_mode (GumElfModule * self)
{
  return self->source_mode;
}

gconstpointer
gum_elf_module_get_file_data (GumElfModule * self,
                              gsize * size)
{
  if (size != NULL)
    *size = self->file_size;

  return self->file_data;
}

void
gum_elf_module_enumerate_segments (GumElfModule * self,
                                   GumFoundElfSegmentFunc func,
                                   gpointer user_data)
{
  guint i;

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * h = &g_array_index (self->phdrs, GumElfPhdr, i);
    GumElfSegmentDetails d;

    if (h->type != GUM_ELF_PHDR_LOAD)
      continue;

    d.vm_address = h->vaddr;
    d.vm_size = h->memsz;
    d.file_offset = h->offset;
    d.file_size = h->filesz;
    d.protection = gum_parse_phdr_protection (h);

    if (!func (&d, user_data))
      return;
  }
}

void
gum_elf_module_enumerate_sections (GumElfModule * self,
                                   GumFoundElfSectionFunc func,
                                   gpointer user_data)
{
  guint i;

  for (i = 0; i != self->shdrs->len; i++)
  {
    const GumElfSectionDetails * d =
        &g_array_index (self->sections, GumElfSectionDetails, i);

    if (!func (d, user_data))
      return;
  }
}

void
gum_elf_module_enumerate_relocations (GumElfModule * self,
                                      GumFoundElfRelocationFunc func,
                                      gpointer user_data)
{
  guint64 relocs_offset, relocs_size, relocs_entsize, minimum_entsize;
  gboolean relocs_have_addend;
  guint64 symtab_offset, symtab_entsize;
  const gchar * strings, * strings_base;
  gsize strings_size;
  gconstpointer data;
  gsize size;
  guint i, n;
  gconstpointer start, end, cursor;
  GError ** error = NULL;

  relocs_offset = 0;
  relocs_size = 0;
  relocs_entsize = 0;
  relocs_have_addend = FALSE;

  symtab_offset = 0;
  symtab_entsize = 0;

  strings = NULL;
  strings_base = NULL;
  strings_size = 0;

  data = gum_elf_module_get_file_data (self, &size);

  for (i = 0; i != self->dyns->len; i++)
  {
    const GumElfDyn * dyn = &g_array_index (self->dyns, GumElfDyn, i);

    switch (dyn->tag)
    {
      case GUM_ELF_DYNAMIC_REL:
      case GUM_ELF_DYNAMIC_RELA:
        relocs_offset = dyn->val;
        relocs_have_addend = dyn->tag == GUM_ELF_DYNAMIC_RELA;
        break;
      case GUM_ELF_DYNAMIC_RELSZ:
      case GUM_ELF_DYNAMIC_RELASZ:
        relocs_size = dyn->val;
        break;
      case GUM_ELF_DYNAMIC_RELENT:
      case GUM_ELF_DYNAMIC_RELAENT:
        relocs_entsize = dyn->val;
        break;
      case GUM_ELF_DYNAMIC_SYMTAB:
        symtab_offset = dyn->val;
        break;
      case GUM_ELF_DYNAMIC_SYMENT:
        symtab_entsize = dyn->val;
        break;
      default:
        break;
    }
  }

  if (relocs_offset == 0)
  {
    for (i = 0; i != self->shdrs->len; i++)
    {
      const GumElfShdr * shdr = &g_array_index (self->shdrs, GumElfShdr, i);

      switch (shdr->type)
      {
        case GUM_ELF_SECTION_REL:
        case GUM_ELF_SECTION_RELA:
        {
          const GumElfShdr * symtab_shdr;

          relocs_offset = shdr->offset;
          relocs_size = shdr->size;
          relocs_entsize = shdr->entsize;
          relocs_have_addend = shdr->type == GUM_ELF_SECTION_RELA;

          symtab_shdr =
              gum_elf_module_find_section_header_by_index (self, shdr->link);
          if (symtab_shdr != NULL)
          {
            const GumElfShdr * strings_shdr;

            symtab_offset = symtab_shdr->offset;
            symtab_entsize = symtab_shdr->entsize;

            strings_shdr = gum_elf_module_find_section_header_by_index (self,
                symtab_shdr->link);
            if (strings_shdr != NULL)
            {
              strings = (const gchar *) data + strings_shdr->offset;
              strings_base = data;
              strings_size = size;
            }
          }

          break;
        }
        default:
          break;
      }
    }
  }
  else
  {
    strings = self->dynamic_strings;
    strings_base = gum_elf_module_get_live_data (self, &strings_size);
  }

  if (relocs_offset == 0 || relocs_size == 0 || relocs_entsize == 0)
    return;
  if (symtab_offset == 0 || symtab_entsize == 0)
    return;
  if (strings == NULL)
    return;

  switch (self->ehdr.identity.klass)
  {
    case GUM_ELF_CLASS_64:
      minimum_entsize = relocs_have_addend ? 24 : 16;
      break;
    case GUM_ELF_CLASS_32:
      minimum_entsize = relocs_have_addend ? 12 : 8;
      break;
    default:
      g_assert_not_reached ();
  }
  if (relocs_entsize < minimum_entsize)
    return;

  n = relocs_size / relocs_entsize;

  start = (const guint8 *) data + relocs_offset;
  end = (const guint8 *) start + relocs_size;
  GUM_CHECK_BOUNDS (start, end, "relocations");

  cursor = start;
  for (i = 0; i != n; i++)
  {
    GumElfRelocationDetails d;
    guint32 sym_index;
    GumElfSymbolDetails sym_details;

    d.addend = 0;

    switch (self->ehdr.identity.klass)
    {
      case GUM_ELF_CLASS_64:
      {
        guint64 info;

        d.address = gum_elf_module_read_uint64 (self, cursor);

        info = gum_elf_module_read_uint64 (self,
            (const guint64 *) ((const guint8 *) cursor + 8));
        d.type = info & GUM_INT32_MASK;
        sym_index = info >> 32;

        if (relocs_have_addend)
        {
          d.addend = gum_elf_module_read_int64 (self,
              (const gint64 *) ((const guint8 *) cursor + 16));
        }

        break;
      }
      case GUM_ELF_CLASS_32:
      {
        guint32 info;

        d.address = gum_elf_module_read_uint32 (self, cursor);

        info = gum_elf_module_read_uint32 (self,
            (const guint32 *) ((const guint8 *) cursor + 4));
        d.type = info & GUM_INT8_MASK;
        sym_index = info >> 8;

        if (relocs_have_addend)
        {
          d.addend = gum_elf_module_read_int32 (self,
              (const gint32 *) ((const guint8 *) cursor + 8));
        }

        break;
      }
      default:
        g_assert_not_reached ();
    }

    if (sym_index != GUM_STN_UNDEF)
    {
      gconstpointer sym_start, sym_end;
      GumElfSym sym_val;

      sym_start =
          (const guint8 *) data + symtab_offset + (sym_index * symtab_entsize);
      sym_end = (const guint8 *) sym_start + symtab_entsize;
      GUM_CHECK_BOUNDS (sym_start, sym_end, "relocation symbol");

      gum_elf_module_read_symbol (self, sym_start, &sym_val);

      gum_elf_module_parse_symbol (self, &sym_val, strings, &sym_details);
      if (!gum_elf_module_check_str_bounds (self, sym_details.name,
            strings_base, strings_size, "relocation symbol name", NULL))
        return;

      d.symbol = &sym_details;
    }
    else
    {
      d.symbol = NULL;
    }

    if (!func (&d, user_data))
      return;

    cursor = (const guint8 *) cursor + relocs_entsize;
  }

propagate_error:
  return;
}

void
gum_elf_module_enumerate_dynamic_entries (GumElfModule * self,
                                          GumFoundElfDynamicEntryFunc func,
                                          gpointer user_data)
{
  guint i;

  for (i = 0; i != self->dyns->len; i++)
  {
    const GumElfDyn * dyn = &g_array_index (self->dyns, GumElfDyn, i);
    GumElfDynamicEntryDetails d;

    d.tag = dyn->tag;
    d.val = dyn->val;

    if (!func (&d, user_data))
      return;
  }
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
  gconstpointer data;
  gsize size;
  GumElfDependencyDetails d;

  if (details->tag != GUM_ELF_DYNAMIC_NEEDED)
    return TRUE;

  data = gum_elf_module_get_live_data (ctx->module, &size);

  d.name = ctx->module->dynamic_strings + details->val;
  if (!gum_elf_module_check_str_bounds (ctx->module, d.name, data, size,
        "dependencies", NULL))
  {
    return TRUE;
  }

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

  if (details->section == NULL &&
      (details->type == GUM_ELF_SYMBOL_FUNC ||
       details->type == GUM_ELF_SYMBOL_OBJECT))
  {
    GumImportDetails d;

    d.type = (details->type == GUM_ELF_SYMBOL_FUNC)
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

  if (details->section != NULL &&
      (details->type == GUM_ELF_SYMBOL_FUNC ||
       details->type == GUM_ELF_SYMBOL_OBJECT) &&
      (details->bind == GUM_ELF_BIND_GLOBAL ||
       details->bind == GUM_ELF_BIND_WEAK))
  {
    GumExportDetails d;

    d.type = (details->type == GUM_ELF_SYMBOL_FUNC)
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
  gsize i;
  gconstpointer data;
  gsize size;
  GError ** error = NULL;

  ctx.pending = 3;
  ctx.found_hash = FALSE;

  ctx.entries = NULL;
  ctx.entry_size = 0;
  ctx.entry_count = 0;

  ctx.module = self;

  gum_elf_module_enumerate_dynamic_entries (self, gum_store_symtab_params,
      &ctx);
  if (ctx.pending != 0 || ctx.entry_count == 0)
    return;

  gum_elf_module_enumerate_sections (self, gum_adjust_symtab_params, &ctx);

  data = gum_elf_module_get_live_data (self, &size);

  for (i = 1; i != ctx.entry_count; i++)
  {
    gconstpointer entry = (const guint8 *) ctx.entries + (i * ctx.entry_size);
    GumElfSym sym;
    GumElfSymbolDetails details;

    gum_elf_module_read_symbol (self, entry, &sym);

    gum_elf_module_parse_symbol (self, &sym, self->dynamic_strings, &details);
    GUM_CHECK_STR_BOUNDS (details.name, "symbol name");

    if (!func (&details, user_data))
      return;
  }

propagate_error:
  return;
}

static void
gum_elf_module_parse_symbol (GumElfModule * self,
                             const GumElfSym * sym,
                             const gchar * strings,
                             GumElfSymbolDetails * d)
{
  GumElfSymbolType type = GUM_ELF_ST_TYPE (sym->info);
  const GumElfSectionDetails * section;

  section = gum_elf_module_find_section_details_by_index (self, sym->shndx);

  if (type == GUM_ELF_SYMBOL_SECTION)
  {
    d->name = (section != NULL) ? section->name : "";
    d->address = self->base_address + sym->value;
  }
  else
  {
    d->name = strings + sym->name;
    d->address = (sym->value != 0)
        ? gum_elf_module_translate_to_online (self, sym->value)
        : 0;
  }

  d->size = sym->size;
  d->type = type;
  d->bind = GUM_ELF_ST_BIND (sym->info);
  d->section = section;
}

static void
gum_elf_module_read_symbol (GumElfModule * self,
                            gconstpointer raw_sym,
                            GumElfSym * sym)
{
#define GUM_READ_SYM_FIELD(name, type) \
    GUM_READ (sym->name, src->name, type)
#define GUM_READ_SYM() \
    G_STMT_START \
    { \
      GUM_READ_SYM_FIELD (name,  uint32); \
      GUM_READ_SYM_FIELD (info,  uint8); \
      GUM_READ_SYM_FIELD (other, uint8); \
      GUM_READ_SYM_FIELD (shndx, uint16); \
      GUM_READ_SYM_FIELD (value, uint64); \
      GUM_READ_SYM_FIELD (size,  uint64); \
    } \
    G_STMT_END
#define GUM_READ_SYM32() \
    G_STMT_START \
    { \
      GUM_READ_SYM_FIELD (name,  uint32); \
      GUM_READ_SYM_FIELD (value, uint32); \
      GUM_READ_SYM_FIELD (size,  uint32); \
      GUM_READ_SYM_FIELD (info,  uint8); \
      GUM_READ_SYM_FIELD (other, uint8); \
      GUM_READ_SYM_FIELD (shndx, uint16); \
    } \
    G_STMT_END

  switch (self->ehdr.identity.klass)
  {
    case GUM_ELF_CLASS_64:
    {
      const GumElfSym * src = raw_sym;
      GUM_READ_SYM ();
      break;
    }
    case GUM_ELF_CLASS_32:
    {
      const GumElfSym32 * src = raw_sym;
      GUM_READ_SYM32 ();
      break;
    }
    default:
      g_assert_not_reached ();
  }

#undef GUM_READ_SYM_FIELD
#undef GUM_READ_SYM
#undef GUM_READ_SYM32
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
  gum_elf_module_enumerate_symbols_in_section (self, GUM_ELF_SECTION_SYMTAB,
      func, user_data);
}

static void
gum_elf_module_enumerate_symbols_in_section (GumElfModule * self,
                                             GumElfSectionType section,
                                             GumFoundElfSymbolFunc func,
                                             gpointer user_data)
{
  const GumElfShdr * shdr, * strings_shdr;
  gconstpointer data;
  gsize size;
  guint64 n, i;
  gconstpointer start, end;
  const gchar * strings;
  gconstpointer cursor;
  GError ** error = NULL;

  shdr = gum_elf_module_find_section_header_by_type (self, section);
  if (shdr == NULL)
    return;

  strings_shdr =
      gum_elf_module_find_section_header_by_index (self, shdr->link);
  if (strings_shdr == NULL)
    return;

  data = gum_elf_module_get_file_data (self, &size);

  n = shdr->size / shdr->entsize;

  start = (const guint8 *) data + shdr->offset;
  end = (const guint8 *) start + (n * shdr->entsize);
  GUM_CHECK_BOUNDS (start, end, "symbols");

  strings = (const gchar *) data + strings_shdr->offset;

  cursor = start;
  for (i = 0; i != n; i++)
  {
    GumElfSym sym;
    GumElfSymbolDetails details;

    gum_elf_module_read_symbol (self, cursor, &sym);

    gum_elf_module_parse_symbol (self, &sym, strings, &details);
    GUM_CHECK_STR_BOUNDS (details.name, "symbol name");

    if (!func (&details, user_data))
      return;

    cursor = (const guint8 *) cursor + shdr->entsize;
  }

propagate_error:
  return;
}

static gboolean
gum_elf_module_find_address_file_offset (GumElfModule * self,
                                         GumAddress address,
                                         guint64 * offset)
{
  const GumElfPhdr * phdr;
  gsize delta;

  phdr = gum_elf_module_find_load_phdr_by_address (self, address);
  if (phdr == NULL)
    return FALSE;

  delta = address - phdr->vaddr;
  if (delta >= phdr->filesz)
    return FALSE;

  *offset = delta;

  return TRUE;
}

static gboolean
gum_elf_module_find_address_protection (GumElfModule * self,
                                        GumAddress address,
                                        GumPageProtection * prot)
{
  const GumElfPhdr * phdr;

  phdr = gum_elf_module_find_load_phdr_by_address (self, address);
  if (phdr == NULL)
    return FALSE;

  *prot = gum_parse_phdr_protection (phdr);

  return TRUE;
}

static GumPageProtection
gum_parse_phdr_protection (const GumElfPhdr * phdr)
{
  GumPageProtection p;

  p = GUM_PAGE_NO_ACCESS;
  if ((phdr->flags & GUM_ELF_PHDR_R) != 0)
    p |= GUM_PAGE_READ;
  if ((phdr->flags & GUM_ELF_PHDR_W) != 0)
    p |= GUM_PAGE_WRITE;
  if ((phdr->flags & GUM_ELF_PHDR_X) != 0)
    p |= GUM_PAGE_EXECUTE;

  return p;
}

static const GumElfPhdr *
gum_elf_module_find_phdr_by_type (GumElfModule * self,
                                  guint32 type)
{
  guint i;

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * h = &g_array_index (self->phdrs, GumElfPhdr, i);

    if (h->type == type)
      return h;
  }

  return NULL;
}

static const GumElfPhdr *
gum_elf_module_find_load_phdr_by_address (GumElfModule * self,
                                          GumAddress address)
{
  guint i;

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * h = &g_array_index (self->phdrs, GumElfPhdr, i);

    if (h->type == GUM_ELF_PHDR_LOAD &&
        address >= h->vaddr &&
        address < h->vaddr + h->memsz)
    {
      return h;
    }
  }

  return NULL;
}

static const GumElfShdr *
gum_elf_module_find_section_header_by_index (GumElfModule * self,
                                             guint i)
{
  if (i == GUM_ELF_SHDR_INDEX_UNDEF)
    return NULL;

  if (i >= self->shdrs->len)
    return NULL;

  return &g_array_index (self->shdrs, GumElfShdr, i);
}

static const GumElfShdr *
gum_elf_module_find_section_header_by_type (GumElfModule * self,
                                            GumElfSectionType type)
{
  guint i;

  for (i = 0; i != self->shdrs->len; i++)
  {
    const GumElfShdr * shdr = &g_array_index (self->shdrs, GumElfShdr, i);

    if ((GumElfSectionType) shdr->type == type)
      return shdr;
  }

  return NULL;
}

static const GumElfSectionDetails *
gum_elf_module_find_section_details_by_index (GumElfModule * self,
                                              guint i)
{
  if (i == GUM_ELF_SHDR_INDEX_UNDEF)
    return NULL;

  if (i >= self->sections->len)
    return NULL;

  return &g_array_index (self->sections, GumElfSectionDetails, i);
}

static GumAddress
gum_elf_module_compute_preferred_address (GumElfModule * self)
{
  guint i;

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * phdr = &g_array_index (self->phdrs, GumElfPhdr, i);

    if (phdr->type == GUM_ELF_PHDR_LOAD && phdr->offset == 0)
      return phdr->vaddr;
  }

  return 0;
}

static guint64
gum_elf_module_compute_mapped_size (GumElfModule * self)
{
  guint64 lowest, highest, page_size;
  guint i;

  lowest = ~G_GUINT64_CONSTANT (0);
  highest = 0;

  page_size = gum_query_page_size ();

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * phdr = &g_array_index (self->phdrs, GumElfPhdr, i);

    if (phdr->type == GUM_ELF_PHDR_LOAD)
    {
      lowest = MIN (GUM_ELF_PAGE_START (phdr->vaddr, page_size), lowest);
      highest = MAX (phdr->vaddr + phdr->memsz, highest);
    }
  }

  return highest - lowest;
}

static GumElfDynamicAddressState
gum_elf_module_detect_dynamic_address_state (GumElfModule * self)
{
  guint i;

  if (self->source_mode == GUM_ELF_SOURCE_MODE_OFFLINE)
    return GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;

  for (i = 0; i != self->dyns->len; i++)
  {
    const GumElfDyn * dyn = &g_array_index (self->dyns, GumElfDyn, i);

    switch (dyn->tag)
    {
      case GUM_ELF_DYNAMIC_SYMTAB:
      case GUM_ELF_DYNAMIC_STRTAB:
        if (dyn->val > self->base_address)
          return GUM_ELF_DYNAMIC_ADDRESS_ADJUSTED;
        break;
    }
  }

  return GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;
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
  if (self->source_mode == GUM_ELF_SOURCE_MODE_ONLINE)
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
gum_elf_module_check_bounds (GumElfModule * self,
                             gconstpointer left,
                             gconstpointer right,
                             gconstpointer base,
                             gsize size,
                             const gchar * name,
                             GError ** error)
{
  const guint8 * l = left;
  const guint8 * r = right;

  if (r < l)
    goto oob;

  if (l < (const guint8 *) base)
    goto oob;

  if (r > (const guint8 *) base + size)
    goto oob;

  return TRUE;

oob:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Missing data while reading %s", name);
    return FALSE;
  }
}

static gboolean
gum_elf_module_check_str_bounds (GumElfModule * self,
                                 const gchar * str,
                                 gconstpointer base,
                                 gsize size,
                                 const gchar * name,
                                 GError ** error)
{
  const gchar * end, * cursor;

  if (str < (const gchar *) base)
    goto oob;

  end = (const gchar *) base + size;

  cursor = str;
  do
  {
    if (cursor >= end)
      goto oob;
  }
  while (*cursor++ != '\0');

  return TRUE;

oob:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Missing data while reading %s", name);
    return FALSE;
  }
}

static guint8
gum_elf_module_read_uint8 (GumElfModule * self,
                           const guint8 * v)
{
  return *v;
}

static guint16
gum_elf_module_read_uint16 (GumElfModule * self,
                            const guint16 * v)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? GUINT16_FROM_LE (*v)
      : GUINT16_FROM_BE (*v);
}

static gint32
gum_elf_module_read_int32 (GumElfModule * self,
                           const gint32 * v)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? GINT32_FROM_LE (*v)
      : GINT32_FROM_BE (*v);
}

static guint32
gum_elf_module_read_uint32 (GumElfModule * self,
                            const guint32 * v)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? GUINT32_FROM_LE (*v)
      : GUINT32_FROM_BE (*v);
}

static gint64
gum_elf_module_read_int64 (GumElfModule * self,
                           const gint64 * v)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? GINT64_FROM_LE (*v)
      : GINT64_FROM_BE (*v);
}

static guint64
gum_elf_module_read_uint64 (GumElfModule * self,
                            const guint64 * v)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? GUINT64_FROM_LE (*v)
      : GUINT64_FROM_BE (*v);
}

static gboolean
gum_maybe_extract_from_apk (const gchar * path,
                            GBytes ** file_bytes)
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

  *file_bytes = g_bytes_new_take (g_steal_pointer (&buffer), size);

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
