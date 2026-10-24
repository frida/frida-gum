/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumpemodule.h"

#define GUM_PE_DOS_MAGIC 0x5a4d
#define GUM_PE_NT_SIGNATURE 0x00004550
#define GUM_PE_OPTIONAL_MAGIC_PE32 0x010b
#define GUM_PE_OPTIONAL_MAGIC_PE32_PLUS 0x020b
#define GUM_PE_ORDINAL_FLAG_32 0x80000000UL
#define GUM_PE_ORDINAL_FLAG_64 G_GUINT64_CONSTANT (0x8000000000000000)

#define GUM_PE_SCN_MEM_EXECUTE 0x20000000
#define GUM_PE_SCN_MEM_READ 0x40000000
#define GUM_PE_SCN_MEM_WRITE 0x80000000

typedef struct _GumPeDosHeader GumPeDosHeader;
typedef struct _GumPeFileHeader GumPeFileHeader;
typedef struct _GumPeOptionalHeader32 GumPeOptionalHeader32;
typedef struct _GumPeOptionalHeader64 GumPeOptionalHeader64;
typedef struct _GumPeSectionHeader GumPeSectionHeader;
typedef struct _GumPeBaseRelocationBlock GumPeBaseRelocationBlock;
typedef struct _GumPeImportDescriptor GumPeImportDescriptor;
typedef struct _GumPeDelayDescriptor GumPeDelayDescriptor;
typedef struct _GumPeExportDirectory GumPeExportDirectory;
typedef struct _GumPeTlsDirectory32 GumPeTlsDirectory32;
typedef struct _GumPeTlsDirectory64 GumPeTlsDirectory64;

typedef struct _GumPeFindExportContext GumPeFindExportContext;

struct _GumPeDosHeader
{
  guint16 e_magic;
  guint16 e_cblp;
  guint16 e_cp;
  guint16 e_crlc;
  guint16 e_cparhdr;
  guint16 e_minalloc;
  guint16 e_maxalloc;
  guint16 e_ss;
  guint16 e_sp;
  guint16 e_csum;
  guint16 e_ip;
  guint16 e_cs;
  guint16 e_lfarlc;
  guint16 e_ovno;
  guint16 e_res[4];
  guint16 e_oemid;
  guint16 e_oeminfo;
  guint16 e_res2[10];
  guint32 e_lfanew;
};

struct _GumPeFileHeader
{
  guint16 machine;
  guint16 number_of_sections;
  guint32 time_date_stamp;
  guint32 pointer_to_symbol_table;
  guint32 number_of_symbols;
  guint16 size_of_optional_header;
  guint16 characteristics;
};

struct _GumPeOptionalHeader32
{
  guint16 magic;
  guint8 major_linker_version;
  guint8 minor_linker_version;
  guint32 size_of_code;
  guint32 size_of_initialized_data;
  guint32 size_of_uninitialized_data;
  guint32 address_of_entry_point;
  guint32 base_of_code;
  guint32 base_of_data;
  guint32 image_base;
  guint32 section_alignment;
  guint32 file_alignment;
  guint16 major_operating_system_version;
  guint16 minor_operating_system_version;
  guint16 major_image_version;
  guint16 minor_image_version;
  guint16 major_subsystem_version;
  guint16 minor_subsystem_version;
  guint32 win32_version_value;
  guint32 size_of_image;
  guint32 size_of_headers;
  guint32 checksum;
  guint16 subsystem;
  guint16 dll_characteristics;
  guint32 size_of_stack_reserve;
  guint32 size_of_stack_commit;
  guint32 size_of_heap_reserve;
  guint32 size_of_heap_commit;
  guint32 loader_flags;
  guint32 number_of_rva_and_sizes;
  GumPeDataDirectory data_directory[16];
};

struct _GumPeOptionalHeader64
{
  guint16 magic;
  guint8 major_linker_version;
  guint8 minor_linker_version;
  guint32 size_of_code;
  guint32 size_of_initialized_data;
  guint32 size_of_uninitialized_data;
  guint32 address_of_entry_point;
  guint32 base_of_code;
  guint64 image_base;
  guint32 section_alignment;
  guint32 file_alignment;
  guint16 major_operating_system_version;
  guint16 minor_operating_system_version;
  guint16 major_image_version;
  guint16 minor_image_version;
  guint16 major_subsystem_version;
  guint16 minor_subsystem_version;
  guint32 win32_version_value;
  guint32 size_of_image;
  guint32 size_of_headers;
  guint32 checksum;
  guint16 subsystem;
  guint16 dll_characteristics;
  guint64 size_of_stack_reserve;
  guint64 size_of_stack_commit;
  guint64 size_of_heap_reserve;
  guint64 size_of_heap_commit;
  guint32 loader_flags;
  guint32 number_of_rva_and_sizes;
  GumPeDataDirectory data_directory[16];
};

struct _GumPeSectionHeader
{
  gchar name[8];
  guint32 virtual_size;
  guint32 virtual_address;
  guint32 size_of_raw_data;
  guint32 pointer_to_raw_data;
  guint32 pointer_to_relocations;
  guint32 pointer_to_linenumbers;
  guint16 number_of_relocations;
  guint16 number_of_linenumbers;
  guint32 characteristics;
};

struct _GumPeBaseRelocationBlock
{
  guint32 virtual_address;
  guint32 size_of_block;
};

struct _GumPeImportDescriptor
{
  guint32 original_first_thunk;
  guint32 time_date_stamp;
  guint32 forwarder_chain;
  guint32 name;
  guint32 first_thunk;
};

struct _GumPeDelayDescriptor
{
  guint32 attributes;
  guint32 name;
  guint32 module_handle;
  guint32 import_address_table;
  guint32 import_name_table;
  guint32 bound_import_address_table;
  guint32 unload_information_table;
  guint32 time_date_stamp;
};

struct _GumPeExportDirectory
{
  guint32 characteristics;
  guint32 time_date_stamp;
  guint16 major_version;
  guint16 minor_version;
  guint32 name;
  guint32 base;
  guint32 number_of_functions;
  guint32 number_of_names;
  guint32 address_of_functions;
  guint32 address_of_names;
  guint32 address_of_name_ordinals;
};

struct _GumPeTlsDirectory32
{
  guint32 start_address_of_raw_data;
  guint32 end_address_of_raw_data;
  guint32 address_of_index;
  guint32 address_of_callbacks;
  guint32 size_of_zero_fill;
  guint32 characteristics;
};

struct _GumPeTlsDirectory64
{
  guint64 start_address_of_raw_data;
  guint64 end_address_of_raw_data;
  guint64 address_of_index;
  guint64 address_of_callbacks;
  guint32 size_of_zero_fill;
  guint32 characteristics;
};

struct _GumPeModule
{
  GObject parent;

  GBytes * blob;
  const guint8 * data;
  gsize size;
  GumAddress online_base;
  GumPeSourceMode source_mode;

  GumPeMachine machine;
  guint pointer_size;
  guint64 image_base;
  gsize size_of_image;
  gsize size_of_headers;
  guint32 entrypoint;
  const GumPeSectionHeader * sections;
  guint16 num_sections;
  GumPeDataDirectory data_directory[16];
};

struct _GumPeFindExportContext
{
  const gchar * name;
  GumPeExportDetails * details;
  gboolean found;
};

static void gum_pe_module_finalize (GObject * object);
static GumPeModule * gum_pe_module_new (GBytes * blob, GumAddress online_base,
    GumPeSourceMode mode, GError ** error);
static gboolean gum_pe_module_load (GumPeModule * self, GError ** error);
static GumPageProtection gum_pe_protection_from_characteristics (
    guint32 characteristics);
static gboolean gum_pe_module_emit_import (GumPeModule * self,
    const gchar * module_name, guint64 value, GumPeImportLoadMode load_mode,
    guint32 slot_rva, GumFoundPeImportFunc func, gpointer user_data);
static gboolean gum_pe_store_export (const GumPeExportDetails * details,
    gpointer user_data);
static void gum_pe_module_read_tls_directory (GumPeModule * self,
    GumPeTlsDirectory64 * tls);
static guint gum_pe_module_get_function_entry_size (GumPeModule * self);

G_DEFINE_TYPE (GumPeModule, gum_pe_module, G_TYPE_OBJECT)

static void
gum_pe_module_class_init (GumPeModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_pe_module_finalize;
}

static void
gum_pe_module_init (GumPeModule * self)
{
}

static void
gum_pe_module_finalize (GObject * object)
{
  GumPeModule * self = GUM_PE_MODULE (object);

  g_clear_pointer (&self->blob, g_bytes_unref);

  G_OBJECT_CLASS (gum_pe_module_parent_class)->finalize (object);
}

GumPeModule *
gum_pe_module_new_from_file (const gchar * path,
                             GError ** error)
{
  gchar * contents;
  gsize length;
  GBytes * blob;

  if (!g_file_get_contents (path, &contents, &length, error))
    return NULL;

  blob = g_bytes_new_take (contents, length);

  return gum_pe_module_new (blob, 0, GUM_PE_SOURCE_MODE_OFFLINE, error);
}

GumPeModule *
gum_pe_module_new_from_blob (GBytes * blob,
                             GError ** error)
{
  return gum_pe_module_new (g_bytes_ref (blob), 0, GUM_PE_SOURCE_MODE_OFFLINE,
      error);
}

GumPeModule *
gum_pe_module_new_from_memory (GumAddress base_address,
                               GError ** error)
{
  return gum_pe_module_new (NULL, base_address, GUM_PE_SOURCE_MODE_ONLINE,
      error);
}

static GumPeModule *
gum_pe_module_new (GBytes * blob,
                   GumAddress online_base,
                   GumPeSourceMode mode,
                   GError ** error)
{
  GumPeModule * module;

  module = g_object_new (GUM_TYPE_PE_MODULE, NULL);
  module->blob = blob;
  module->online_base = online_base;
  module->source_mode = mode;

  if (blob != NULL)
    module->data = g_bytes_get_data (blob, &module->size);
  else
    module->data = GSIZE_TO_POINTER (online_base);

  if (!gum_pe_module_load (module, error))
  {
    g_object_unref (module);
    return NULL;
  }

  return module;
}

static gboolean
gum_pe_module_load (GumPeModule * self,
                    GError ** error)
{
  const guint8 * data = self->data;
  const GumPeDosHeader * dos;
  guint32 nt_offset, signature;
  const GumPeFileHeader * file_header;
  const guint8 * optional_header;
  guint16 magic;
  guint num_directories, i;
  const GumPeDataDirectory * directories;

  dos = (const GumPeDosHeader *) data;
  if (self->size >= sizeof (GumPeDosHeader) && dos->e_magic != GUM_PE_DOS_MAGIC)
    goto invalid_data;

  nt_offset = dos->e_lfanew;
  signature = *((const guint32 *) (data + nt_offset));
  if (signature != GUM_PE_NT_SIGNATURE)
    goto invalid_data;

  file_header = (const GumPeFileHeader *) (data + nt_offset + 4);
  optional_header = (const guint8 *) (file_header + 1);
  magic = *((const guint16 *) optional_header);

  self->machine = file_header->machine;
  self->num_sections = file_header->number_of_sections;
  self->sections = (const GumPeSectionHeader *)
      (optional_header + file_header->size_of_optional_header);

  if (magic == GUM_PE_OPTIONAL_MAGIC_PE32_PLUS)
  {
    const GumPeOptionalHeader64 * oh =
        (const GumPeOptionalHeader64 *) optional_header;

    self->pointer_size = 8;
    self->image_base = oh->image_base;
    self->size_of_image = oh->size_of_image;
    self->size_of_headers = oh->size_of_headers;
    self->entrypoint = oh->address_of_entry_point;
    num_directories = oh->number_of_rva_and_sizes;
    directories = oh->data_directory;
  }
  else if (magic == GUM_PE_OPTIONAL_MAGIC_PE32)
  {
    const GumPeOptionalHeader32 * oh =
        (const GumPeOptionalHeader32 *) optional_header;

    self->pointer_size = 4;
    self->image_base = oh->image_base;
    self->size_of_image = oh->size_of_image;
    self->size_of_headers = oh->size_of_headers;
    self->entrypoint = oh->address_of_entry_point;
    num_directories = oh->number_of_rva_and_sizes;
    directories = oh->data_directory;
  }
  else
  {
    goto invalid_data;
  }

  if (num_directories > 16)
    num_directories = 16;
  for (i = 0; i != num_directories; i++)
    self->data_directory[i] = directories[i];

  return TRUE;

invalid_data:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Not a valid PE image");
    return FALSE;
  }
}

guint
gum_pe_module_get_pointer_size (GumPeModule * self)
{
  return self->pointer_size;
}

GumPeMachine
gum_pe_module_get_machine (GumPeModule * self)
{
  return self->machine;
}

guint64
gum_pe_module_get_image_base (GumPeModule * self)
{
  return self->image_base;
}

gsize
gum_pe_module_get_size_of_image (GumPeModule * self)
{
  return self->size_of_image;
}

gsize
gum_pe_module_get_size_of_headers (GumPeModule * self)
{
  return self->size_of_headers;
}

guint32
gum_pe_module_get_entrypoint (GumPeModule * self)
{
  return self->entrypoint;
}

GBytes *
gum_pe_module_get_source_blob (GumPeModule * self)
{
  return self->blob;
}

GumPeSourceMode
gum_pe_module_get_source_mode (GumPeModule * self)
{
  return self->source_mode;
}

const GumPeDataDirectory *
gum_pe_module_get_directory (GumPeModule * self,
                             GumPeDirectoryIndex index)
{
  return &self->data_directory[index];
}

gconstpointer
gum_pe_module_get_data_at_rva (GumPeModule * self,
                               guint32 rva)
{
  guint16 i;

  if (self->source_mode == GUM_PE_SOURCE_MODE_ONLINE)
    return self->data + rva;

  if (rva < self->size_of_headers)
    return self->data + rva;

  for (i = 0; i != self->num_sections; i++)
  {
    const GumPeSectionHeader * s = &self->sections[i];

    if (rva >= s->virtual_address &&
        rva < s->virtual_address + s->size_of_raw_data)
    {
      return self->data + s->pointer_to_raw_data + (rva - s->virtual_address);
    }
  }

  return NULL;
}

void
gum_pe_module_enumerate_sections (GumPeModule * self,
                                  GumFoundPeSectionFunc func,
                                  gpointer user_data)
{
  guint16 i;

  for (i = 0; i != self->num_sections; i++)
  {
    const GumPeSectionHeader * s = &self->sections[i];
    gchar name[9];
    GumPeSectionDetails details;

    memcpy (name, s->name, 8);
    name[8] = '\0';

    details.name = name;
    details.virtual_address = s->virtual_address;
    details.virtual_size = s->virtual_size;
    details.raw_data_offset = s->pointer_to_raw_data;
    details.raw_data_size = s->size_of_raw_data;
    details.characteristics = s->characteristics;
    details.protection =
        gum_pe_protection_from_characteristics (s->characteristics);

    if (!func (&details, user_data))
      return;
  }
}

static GumPageProtection
gum_pe_protection_from_characteristics (guint32 characteristics)
{
  GumPageProtection prot = GUM_PAGE_NO_ACCESS;

  if ((characteristics & GUM_PE_SCN_MEM_READ) != 0)
    prot |= GUM_PAGE_READ;
  if ((characteristics & GUM_PE_SCN_MEM_WRITE) != 0)
    prot |= GUM_PAGE_WRITE;
  if ((characteristics & GUM_PE_SCN_MEM_EXECUTE) != 0)
    prot |= GUM_PAGE_EXECUTE;

  return prot;
}

void
gum_pe_module_enumerate_relocations (GumPeModule * self,
                                     GumFoundPeRelocationFunc func,
                                     gpointer user_data)
{
  const GumPeDataDirectory * dir =
      &self->data_directory[GUM_PE_DIRECTORY_BASERELOC];
  const guint8 * cursor;
  const guint8 * end;

  if (dir->size == 0)
    return;

  cursor = gum_pe_module_get_data_at_rva (self, dir->rva);
  end = cursor + dir->size;

  while (cursor < end)
  {
    const GumPeBaseRelocationBlock * block =
        (const GumPeBaseRelocationBlock *) cursor;
    guint count, i;
    const guint16 * entries = (const guint16 *) (block + 1);

    count = (block->size_of_block - sizeof (GumPeBaseRelocationBlock)) /
        sizeof (guint16);

    for (i = 0; i != count; i++)
    {
      guint16 entry = entries[i];
      GumPeRelocationDetails details;

      details.rva = block->virtual_address + (entry & 0xfff);
      details.type = entry >> 12;

      if (!func (&details, user_data))
        return;
    }

    cursor += block->size_of_block;
  }
}

void
gum_pe_module_enumerate_imports (GumPeModule * self,
                                 GumFoundPeImportFunc func,
                                 gpointer user_data)
{
  const GumPeDataDirectory * imports =
      &self->data_directory[GUM_PE_DIRECTORY_IMPORT];
  guint pointer_size = self->pointer_size;
  const GumPeDataDirectory * delay =
      &self->data_directory[GUM_PE_DIRECTORY_DELAY_IMPORT];

  if (imports->size != 0)
  {
    const GumPeImportDescriptor * desc =
        gum_pe_module_get_data_at_rva (self, imports->rva);

    for (; desc->name != 0; desc++)
    {
      guint i;
      guint32 lookup_rva =
          (desc->original_first_thunk != 0)
          ? desc->original_first_thunk
          : desc->first_thunk;
      const guint8 * lookup =
          gum_pe_module_get_data_at_rva (self, lookup_rva);
      const gchar * module_name =
          gum_pe_module_get_data_at_rva (self, desc->name);

      if (desc->original_first_thunk == 0 &&
          self->source_mode == GUM_PE_SOURCE_MODE_ONLINE)
        continue;

      for (i = 0; ; i++)
      {
        guint64 value;

        value = (pointer_size == 8)
            ? ((const guint64 *) lookup)[i]
            : ((const guint32 *) lookup)[i];
        if (value == 0)
          break;

        if (!gum_pe_module_emit_import (self, module_name, value,
            GUM_PE_IMPORT_LOAD_MODE_REGULAR,
            desc->first_thunk + (i * pointer_size), func, user_data))
          return;
      }
    }
  }

  if (delay->size != 0)
  {
    const GumPeDelayDescriptor * desc =
        gum_pe_module_get_data_at_rva (self, delay->rva);

    for (; desc->name != 0; desc++)
    {
      guint i;
      const guint8 * lookup =
          gum_pe_module_get_data_at_rva (self, desc->import_name_table);
      const gchar * module_name =
          gum_pe_module_get_data_at_rva (self, desc->name);

      for (i = 0; ; i++)
      {
        guint64 value;

        value = (pointer_size == 8)
            ? ((const guint64 *) lookup)[i]
            : ((const guint32 *) lookup)[i];
        if (value == 0)
          break;

        if (!gum_pe_module_emit_import (self, module_name, value,
            GUM_PE_IMPORT_LOAD_MODE_DELAYED,
            desc->import_address_table + (i * pointer_size), func, user_data))
          return;
      }
    }
  }
}

static gboolean
gum_pe_module_emit_import (GumPeModule * self,
                           const gchar * module_name,
                           guint64 value,
                           GumPeImportLoadMode load_mode,
                           guint32 slot_rva,
                           GumFoundPeImportFunc func,
                           gpointer user_data)
{
  GumPeImportDetails details;
  guint64 ordinal_flag = (self->pointer_size == 8)
      ? GUM_PE_ORDINAL_FLAG_64
      : GUM_PE_ORDINAL_FLAG_32;

  details.type = ((value & ordinal_flag) == 0)
      ? GUM_PE_IMPORT_BY_NAME
      : GUM_PE_IMPORT_BY_ORDINAL;
  details.load_mode = load_mode;
  details.module_name = module_name;
  details.slot_rva = slot_rva;

  if (details.type == GUM_PE_IMPORT_BY_NAME)
  {
    const guint8 * hint_name = gum_pe_module_get_data_at_rva (self, value);

    details.name = (const gchar *) (hint_name + 2);
  }
  else
  {
    details.ordinal = value & 0xffff;
  }

  return func (&details, user_data);
}

gboolean
gum_pe_module_find_export_by_name (GumPeModule * self,
                                   const gchar * name,
                                   GumPeExportDetails * details)
{
  GumPeFindExportContext ctx;

  ctx.name = name;
  ctx.details = details;
  ctx.found = FALSE;

  gum_pe_module_enumerate_exports (self, gum_pe_store_export, &ctx);

  return ctx.found;
}

static gboolean
gum_pe_store_export (const GumPeExportDetails * details,
                     gpointer user_data)
{
  GumPeFindExportContext * ctx = user_data;

  if (details->name == NULL || strcmp (details->name, ctx->name) != 0)
    return TRUE;

  *ctx->details = *details;
  ctx->found = TRUE;

  return FALSE;
}

void
gum_pe_module_enumerate_exports (GumPeModule * self,
                                 GumFoundPeExportFunc func,
                                 gpointer user_data)
{
  const GumPeDataDirectory * dir =
      &self->data_directory[GUM_PE_DIRECTORY_EXPORT];
  const GumPeExportDirectory * exp;
  const guint32 * names;
  const guint16 * ordinals;
  const gchar ** name_by_index;
  guint32 i;
  const guint32 * functions;

  if (dir->size == 0)
    return;

  exp = gum_pe_module_get_data_at_rva (self, dir->rva);
  names = gum_pe_module_get_data_at_rva (self, exp->address_of_names);
  ordinals =
      gum_pe_module_get_data_at_rva (self, exp->address_of_name_ordinals);

  name_by_index = g_new0 (const gchar *, exp->number_of_functions);
  for (i = 0; i != exp->number_of_names; i++)
  {
    name_by_index[ordinals[i]] =
        gum_pe_module_get_data_at_rva (self, names[i]);
  }

  functions = gum_pe_module_get_data_at_rva (self, exp->address_of_functions);

  for (i = 0; i != exp->number_of_functions; i++)
  {
    guint32 func_rva = functions[i];
    GumPeExportDetails details;

    if (func_rva == 0)
      continue;

    details.type = (func_rva >= dir->rva && func_rva < dir->rva + dir->size)
        ? GUM_PE_EXPORT_FORWARDED
        : GUM_PE_EXPORT_REGULAR;
    details.ordinal = exp->base + i;
    details.name = name_by_index[i];

    if (details.type == GUM_PE_EXPORT_REGULAR)
      details.rva = func_rva;
    else
      details.forwarder = gum_pe_module_get_data_at_rva (self, func_rva);

    if (!func (&details, user_data))
      break;
  }

  g_free (name_by_index);
}

gboolean
gum_pe_module_get_tls_details (GumPeModule * self,
                               GumPeTlsDetails * details)
{
  GumPeTlsDirectory64 tls;

  if (self->data_directory[GUM_PE_DIRECTORY_TLS].size == 0)
    return FALSE;

  gum_pe_module_read_tls_directory (self, &tls);

  details->template_rva = tls.start_address_of_raw_data - self->image_base;
  details->template_size =
      tls.end_address_of_raw_data - tls.start_address_of_raw_data;
  details->index_rva = tls.address_of_index - self->image_base;

  return TRUE;
}

void
gum_pe_module_enumerate_tls_callbacks (GumPeModule * self,
                                       GumFoundPeTlsCallbackFunc func,
                                       gpointer user_data)
{
  GumPeTlsDirectory64 tls;
  guint32 callbacks_rva;
  const guint8 * callbacks;
  guint i;

  if (self->data_directory[GUM_PE_DIRECTORY_TLS].size == 0)
    return;

  gum_pe_module_read_tls_directory (self, &tls);
  if (tls.address_of_callbacks == 0)
    return;

  callbacks_rva = tls.address_of_callbacks - self->image_base;
  callbacks = gum_pe_module_get_data_at_rva (self, callbacks_rva);

  for (i = 0; ; i++)
  {
    guint64 callback_va = (self->pointer_size == 8)
        ? ((const guint64 *) callbacks)[i]
        : ((const guint32 *) callbacks)[i];

    if (callback_va == 0)
      break;

    if (!func (callback_va - self->image_base, user_data))
      return;
  }
}

static void
gum_pe_module_read_tls_directory (GumPeModule * self,
                                  GumPeTlsDirectory64 * tls)
{
  gconstpointer raw = gum_pe_module_get_data_at_rva (self,
      self->data_directory[GUM_PE_DIRECTORY_TLS].rva);

  if (self->pointer_size == 8)
  {
    *tls = *((const GumPeTlsDirectory64 *) raw);
  }
  else
  {
    const GumPeTlsDirectory32 * tls32 = raw;

    tls->start_address_of_raw_data = tls32->start_address_of_raw_data;
    tls->end_address_of_raw_data = tls32->end_address_of_raw_data;
    tls->address_of_index = tls32->address_of_index;
    tls->address_of_callbacks = tls32->address_of_callbacks;
    tls->size_of_zero_fill = tls32->size_of_zero_fill;
    tls->characteristics = tls32->characteristics;
  }
}

void
gum_pe_module_enumerate_dependencies (GumPeModule * self,
                                      GumFoundDependencyFunc func,
                                      gpointer user_data)
{
  const GumPeDataDirectory * imports =
      &self->data_directory[GUM_PE_DIRECTORY_IMPORT];
  GumDependencyDetails details;
  const GumPeDataDirectory * delay =
      &self->data_directory[GUM_PE_DIRECTORY_DELAY_IMPORT];

  if (imports->size != 0)
  {
    const GumPeImportDescriptor * desc =
        gum_pe_module_get_data_at_rva (self, imports->rva);

    details.type = GUM_DEPENDENCY_REGULAR;

    for (; desc->name != 0; desc++)
    {
      details.name = gum_pe_module_get_data_at_rva (self, desc->name);

      if (!func (&details, user_data))
        return;
    }
  }

  if (delay->size != 0)
  {
    const GumPeDelayDescriptor * desc =
        gum_pe_module_get_data_at_rva (self, delay->rva);

    details.type = GUM_DEPENDENCY_WEAK;

    for (; desc->name != 0; desc++)
    {
      details.name = gum_pe_module_get_data_at_rva (self, desc->name);

      if (!func (&details, user_data))
        return;
    }
  }
}

guint
gum_pe_module_get_function_count (GumPeModule * self)
{
  return self->data_directory[GUM_PE_DIRECTORY_EXCEPTION].size /
      gum_pe_module_get_function_entry_size (self);
}

void
gum_pe_module_enumerate_function_starts (GumPeModule * self,
                                         GumFoundPeFunctionStartFunc func,
                                         gpointer user_data)
{
  guint count = gum_pe_module_get_function_count (self);
  const guint8 * entries;
  guint entry_size;
  guint i;

  if (count == 0)
    return;

  entries = gum_pe_module_get_data_at_rva (self,
      self->data_directory[GUM_PE_DIRECTORY_EXCEPTION].rva);
  entry_size = gum_pe_module_get_function_entry_size (self);

  for (i = 0; i != count; i++)
  {
    guint32 begin_rva = *((const guint32 *) (entries + (i * entry_size)));

    if (!func (begin_rva, user_data))
      return;
  }
}

static guint
gum_pe_module_get_function_entry_size (GumPeModule * self)
{
  return (self->machine == GUM_PE_MACHINE_AMD64) ? 12 : 8;
}
