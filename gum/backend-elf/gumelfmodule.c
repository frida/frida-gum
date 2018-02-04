/*
 * Copyright (C) 2010-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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

typedef struct _GumElfEnumerateDepsContext GumElfEnumerateDepsContext;
typedef struct _GumElfEnumerateImportsContext GumElfEnumerateImportsContext;
typedef struct _GumElfEnumerateExportsContext GumElfEnumerateExportsContext;
typedef struct _GumElfStoreSymtabParamsContext GumElfStoreSymtabParamsContext;

struct _GumElfEnumerateDepsContext
{
  GumElfFoundDependencyFunc func;
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

static gboolean gum_emit_each_needed (const GumElfDynamicEntryDetails * details,
    gpointer user_data);
static gboolean gum_emit_elf_import (const GumElfSymbolDetails * details,
    gpointer user_data);
static gboolean gum_emit_elf_export (const GumElfSymbolDetails * details,
    gpointer user_data);
static gboolean gum_store_symtab_params (
    const GumElfDynamicEntryDetails * details, gpointer user_data);
static void gum_elf_module_enumerate_symbols_in_section (GumElfModule * self,
    GumElfSectionHeaderType section, GumElfFoundSymbolFunc func,
    gpointer user_data);
static gboolean gum_elf_module_find_dynamic_range (GumElfModule * self,
    GumMemoryRange * range);
static GumAddress gum_elf_module_compute_preferred_address (
    GumElfModule * self);
static GumElfDynamicAddressState gum_elf_module_detect_dynamic_address_state (
    GumElfModule * self);
static GumAddress gum_elf_module_resolve_static_virtual_address (
    GumElfModule * self, GumAddress address);
static GumAddress gum_elf_module_resolve_dynamic_virtual_address (
    GumElfModule * self, GumAddress address);
static gboolean gum_store_dynamic_string_table (
    const GumElfDynamicEntryDetails * details, gpointer user_data);

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
      G_MAXUINT64, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
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

  if (details->type != DT_NEEDED)
    return TRUE;

  d.name = ctx->module->dynamic_strings + details->value;

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
  const gchar * linker_name = (sizeof (gpointer) == 4)
      ? "/system/bin/linker"
      : "/system/bin/linker64";
  if (strcmp (self->path, linker_name) == 0)
  {
    const gchar * linker_exports[] =
    {
      "dlopen",
      "dlsym",
      "dlclose",
      "dlerror",
    };
    guint i;

    for (i = 0; i != G_N_ELEMENTS (linker_exports); i++)
    {
      const gchar * name = linker_exports[i];
      GumExportDetails d;

      d.type = GUM_EXPORT_FUNCTION;
      d.name = name;
      d.address = gum_module_find_export_by_name (linker_name, name);
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
                                          GumElfFoundSymbolFunc func,
                                          gpointer user_data)
{
  GumElfStoreSymtabParamsContext ctx;
  gsize entry_index;
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

  for (entry_index = 1; entry_index != ctx.entry_count; entry_index++)
  {
    gpointer entry = ctx.entries + (entry_index * ctx.entry_size);
    GumElfSymbolDetails details;
    GumAddress raw_address;

    if (sizeof (gpointer) == 4)
    {
      Elf32_Sym * sym = entry;

      details.name = dynamic_strings + sym->st_name;
      details.type = GELF_ST_TYPE (sym->st_info);
      details.bind = GELF_ST_BIND (sym->st_info);
      details.section_header_index = sym->st_shndx;

      raw_address = sym->st_value;
    }
    else
    {
      Elf64_Sym * sym = entry;

      details.name = dynamic_strings + sym->st_name;
      details.type = GELF_ST_TYPE (sym->st_info);
      details.bind = GELF_ST_BIND (sym->st_info);
      details.section_header_index = sym->st_shndx;

      raw_address = sym->st_value;
    }

    details.address = (raw_address != 0)
        ? gum_elf_module_resolve_static_virtual_address (self, raw_address)
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

  switch (details->type)
  {
    case DT_SYMTAB:
      ctx->entries = GSIZE_TO_POINTER (
          gum_elf_module_resolve_dynamic_virtual_address (ctx->module,
              details->value));
      ctx->pending--;
      break;
    case DT_SYMENT:
      ctx->entry_size = details->value;
      ctx->pending--;
      break;
    case DT_HASH:
    {
      const guint32 * hash_params;
      guint32 nchain;

      if (ctx->found_hash)
        break;
      ctx->found_hash = TRUE;

      hash_params = GSIZE_TO_POINTER (
          gum_elf_module_resolve_dynamic_virtual_address (ctx->module,
              details->value));
      nchain = hash_params[1];

      ctx->entry_count = nchain;
      ctx->pending--;

      break;
    }
    case DT_GNU_HASH:
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

      hash_params = GSIZE_TO_POINTER (
          gum_elf_module_resolve_dynamic_virtual_address (ctx->module,
              details->value));
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

      while (TRUE)
      {
        guint32 hash = chain[highest_index - symoffset];

        if ((hash & 1) != 0)
          break;

        highest_index++;
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
        ? gum_elf_module_resolve_static_virtual_address (self, sym.st_value)
        : 0;
    details.type = GELF_ST_TYPE (sym.st_info);
    details.bind = GELF_ST_BIND (sym.st_info);
    details.section_header_index = sym.st_shndx;

    carry_on = func (&details, user_data);
  }
}

void
gum_elf_module_enumerate_dynamic_entries (GumElfModule * self,
                                          GumElfFoundDynamicEntryFunc func,
                                          gpointer user_data)
{
  GumMemoryRange dynamic;
  gpointer dynamic_begin;

  if (!gum_elf_module_find_dynamic_range (self, &dynamic))
    return;

  dynamic_begin = GSIZE_TO_POINTER (
      gum_elf_module_resolve_static_virtual_address (self,
          dynamic.base_address));

  if (sizeof (gpointer) == 4)
  {
    Elf32_Dyn * entries;
    guint entry_count, entry_index;

    entries = dynamic_begin;
    entry_count = dynamic.size / sizeof (Elf32_Dyn);

    for (entry_index = 0; entry_index != entry_count; entry_index++)
    {
      Elf32_Dyn * entry = &entries[entry_index];
      GumElfDynamicEntryDetails d;

      d.type = entry->d_tag;
      d.value = entry->d_un.d_val;

      if (!func (&d, user_data))
        return;
    }
  }
  else
  {
    Elf64_Dyn * entries;
    guint entry_count, entry_index;

    entries = dynamic_begin;
    entry_count = dynamic.size / sizeof (Elf64_Dyn);

    for (entry_index = 0; entry_index != entry_count; entry_index++)
    {
      Elf64_Dyn * entry = &entries[entry_index];
      GumElfDynamicEntryDetails d;

      d.type = entry->d_tag;
      d.value = entry->d_un.d_val;

      if (!func (&d, user_data))
        return;
    }
  }
}

static gboolean
gum_elf_module_find_address_protection (GumElfModule * self,
                                        GumAddress address,
                                        GumPageProtection * prot)
{
  GElf_Half header_count, header_index;

  header_count = self->ehdr->e_phnum;
  for (header_index = 0; header_index != header_count; header_index++)
  {
    GElf_Phdr phdr;

    gelf_getphdr (self->elf, header_index, &phdr);

    if (phdr.p_type == PT_LOAD &&
        address >= phdr.p_vaddr &&
        address < phdr.p_vaddr + phdr.p_memsz)
    {
      GumPageProtection p;

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
  }

  return FALSE;
}

static gboolean
gum_elf_module_find_dynamic_range (GumElfModule * self,
                                   GumMemoryRange * range)
{
  GElf_Half header_count, header_index;

  header_count = self->ehdr->e_phnum;
  for (header_index = 0; header_index != header_count; header_index++)
  {
    GElf_Phdr phdr;

    gelf_getphdr (self->elf, header_index, &phdr);

    if (phdr.p_type == PT_DYNAMIC)
    {
      range->base_address = phdr.p_vaddr;
      range->size = phdr.p_memsz;
      return TRUE;
    }
  }

  return FALSE;
}

void
gum_elf_module_enumerate_sections (GumElfModule * self,
                                   GumElfFoundSectionFunc func,
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
    d.address =
        gum_elf_module_resolve_static_virtual_address (self, shdr.sh_addr);
    d.offset = shdr.sh_offset;
    d.size = shdr.sh_size;
    d.link = shdr.sh_link;
    d.info = shdr.sh_info;
    d.alignment = shdr.sh_addralign;
    d.entry_size = shdr.sh_entsize;
    if (!gum_elf_module_find_address_protection (self, shdr.sh_addr, &d.prot))
      d.prot = GUM_PAGE_NO_ACCESS;

    if (!func (&d, user_data))
      return;
  }
}

gboolean
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

gboolean
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
#ifdef HAVE_ANDROID
  return GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;
#else
  return GUM_ELF_DYNAMIC_ADDRESS_ADJUSTED;
#endif
}

static GumAddress
gum_elf_module_resolve_static_virtual_address (GumElfModule * self,
                                               GumAddress address)
{
  return self->base_address + (address - self->preferred_address);
}

static GumAddress
gum_elf_module_resolve_dynamic_virtual_address (GumElfModule * self,
                                                GumAddress address)
{
  switch (self->dynamic_address_state)
  {
    case GUM_ELF_DYNAMIC_ADDRESS_PRISTINE:
      return gum_elf_module_resolve_static_virtual_address (self, address);
    case GUM_ELF_DYNAMIC_ADDRESS_ADJUSTED:
      return address;
    default:
      g_assert_not_reached ();
  }

  return 0;
}

static gboolean
gum_store_dynamic_string_table (const GumElfDynamicEntryDetails * details,
                                gpointer user_data)
{
  GumElfModule * self = user_data;

  if (details->type != DT_STRTAB)
    return TRUE;

  self->dynamic_strings = GSIZE_TO_POINTER (
      gum_elf_module_resolve_dynamic_virtual_address (self, details->value));
  return FALSE;
}
