/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumelfmodule.h"
#include "gummapper.h"
#include "gumnativeprocessmemory.h"
#if defined (HAVE_I386)
# include "gumx86writer.h"
#elif defined (HAVE_ARM)
# include "gumarmwriter.h"
#elif defined (HAVE_ARM64)
# include "gumarm64writer.h"
#elif defined (HAVE_MIPS)
# include "gummipswriter.h"
#endif

#include <string.h>
#include <gio/gio.h>

#define GUM_ELF_MAPPER_CODE_BASE_SIZE 512
#define GUM_ELF_MAPPER_CALL_SIZE 128
#define GUM_ELF_MAPPER_TLS_CODE_SIZE 1024
#define GUM_ELF_MAPPER_INDIRECT_BASE_SIZE 256
#define GUM_ELF_MAPPER_INDIRECT_STORE_SIZE 48
#define GUM_ELF_TLS_MODULE_ID 1

#define GUM_ELF_STAGED(self, address) \
    ((self)->staging + ((address) - (self)->image_address))

#define GUM_ELF_R_386_32 1
#define GUM_ELF_R_386_GLOB_DAT 6
#define GUM_ELF_R_386_JMP_SLOT 7
#define GUM_ELF_R_386_RELATIVE 8
#define GUM_ELF_R_386_TLS_DTPMOD32 35
#define GUM_ELF_R_386_TLS_DTPOFF32 36

#define GUM_ELF_R_X86_64_64 1
#define GUM_ELF_R_X86_64_GLOB_DAT 6
#define GUM_ELF_R_X86_64_JUMP_SLOT 7
#define GUM_ELF_R_X86_64_RELATIVE 8
#define GUM_ELF_R_X86_64_DTPMOD64 16
#define GUM_ELF_R_X86_64_DTPOFF64 17

#define GUM_ELF_R_ARM_ABS32 2
#define GUM_ELF_R_ARM_GLOB_DAT 21
#define GUM_ELF_R_ARM_JUMP_SLOT 22
#define GUM_ELF_R_ARM_RELATIVE 23
#define GUM_ELF_R_ARM_TLS_DTPMOD32 17
#define GUM_ELF_R_ARM_TLS_DTPOFF32 18

#define GUM_ELF_R_AARCH64_ABS64 257
#define GUM_ELF_R_AARCH64_GLOB_DAT 1025
#define GUM_ELF_R_AARCH64_JUMP_SLOT 1026
#define GUM_ELF_R_AARCH64_RELATIVE 1027
#define GUM_ELF_R_AARCH64_TLS_DTPMOD 1028
#define GUM_ELF_R_AARCH64_TLS_DTPREL 1029
#define GUM_ELF_R_AARCH64_TLSDESC 1031

#define GUM_ELF_R_MIPS_32 2
#define GUM_ELF_R_MIPS_REL32 3
#define GUM_ELF_R_MIPS_64 18
#define GUM_ELF_R_MIPS_GLOB_DAT 51
#define GUM_ELF_R_MIPS_TLS_DTPMOD32 38
#define GUM_ELF_R_MIPS_TLS_DTPREL32 39
#define GUM_ELF_R_MIPS_TLS_DTPMOD64 40
#define GUM_ELF_R_MIPS_TLS_DTPREL64 41
#define GUM_ELF_R_MIPS_JUMP_SLOT 127
#define GUM_ELF_MIPS_GOT1_RESERVED_MASK 0x80000000
#define GUM_ELF_MIPS_DTP_OFFSET 0x8000

#define GUM_ELF_SHN_UNDEF 0

#define GUM_ELF_AT_NULL 0
#define GUM_ELF_AT_HWCAP 16
#define GUM_ELF_AT_HWCAP2 26
#define GUM_ELF_IFUNC_ARG_HWCAP (G_GUINT64_CONSTANT (1) << 62)

#if defined (HAVE_MIPS)
# define GUM_ELF_MIPS_FRAME_ARG_AREA_SIZE \
    ((GLIB_SIZEOF_VOID_P == 8) ? 0 : 16)
# define GUM_ELF_MIPS_FRAME_SIZE(n_saved) \
    GUM_ALIGN_SIZE (GUM_ELF_MIPS_FRAME_ARG_AREA_SIZE + \
        ((n_saved) * GLIB_SIZEOF_VOID_P), 16)
# define GUM_ELF_MIPS_FRAME_SLOT(index) \
    (GUM_ELF_MIPS_FRAME_ARG_AREA_SIZE + ((index) * GLIB_SIZEOF_VOID_P))
#endif

#define GUM_TYPE_ELF_MAPPER (gum_elf_mapper_get_type ())
G_DECLARE_FINAL_TYPE (GumElfMapper, gum_elf_mapper, GUM, ELF_MAPPER, GObject)

typedef struct _GumElfInitFini GumElfInitFini;
typedef struct _GumElfRelocationKind GumElfRelocationKind;
typedef struct _GumElfIndirectBinding GumElfIndirectBinding;
typedef struct _GumElfMipsGot GumElfMipsGot;
typedef struct _GumElfIndirectSlot GumElfIndirectSlot;
typedef struct _GumElfTlsLayout GumElfTlsLayout;
typedef struct _GumElfTlsApi GumElfTlsApi;

struct _GumElfTlsLayout
{
  gsize image_size;
  gsize memory_size;
  gsize template_rva;
};

struct _GumElfTlsApi
{
  GumAddress key_create;
  GumAddress key_delete;
  GumAddress getspecific;
  GumAddress setspecific;
  GumAddress calloc;
  const GumDynamicSymbolDetails * memcpy;
  GumAddress free;
};

struct _GumElfMapper
{
  GObject parent;

  gchar * name;
  gchar * path;
  GBytes * blob;
  GumElfModule * module;
  GumModuleResolver * resolver;
  GumProcessMemory * target;
  guint8 * staging;
  GumMemoryRange range;

  GumCpuType cpu_type;
  GumElfMachine machine;
  guint pointer_size;
  GumAddress preferred_address;

  gsize vm_size;
  gsize runtime_code_size;
  gsize runtime_vm_size;
  gsize runtime_file_size;
  guint init_count;
  guint fini_count;
  GumElfTlsLayout tls;

  gpointer runtime;
  GumAddress runtime_address;
  GumAddress image_address;
  GumAddress load_bias;
  gsize constructor_offset;
  gsize destructor_offset;
  GumAddress tls_get_addr;
  GumAddress tls_desc_resolver;
  GumAddress tls_key;
  GumAddress tls_memcpy;
  GumAddress tls_template;
  GumElfTlsApi tls_api;
  guint64 hwcap;
  guint64 hwcap2;
  const gchar * unresolved_symbol;

  GHashTable * symbols;
  GPtrArray * indirect_bindings;
  GHashTable * indirect_binding_by_resolver;
  guint indirect_slot_count;

  GArray * init_functions;
  GArray * fini_functions;
  GArray * tls_desc_slots;
};

enum
{
  PROP_0,
  PROP_NAME,
  PROP_PATH,
  PROP_BLOB,
  PROP_RESOLVER
};

struct _GumElfInitFini
{
  GumElfMapper * mapper;
  GumAddress init_function;
  GumAddress init_array;
  gsize init_array_size;
  GumAddress fini_function;
  GumAddress fini_array;
  gsize fini_array_size;
};

struct _GumElfRelocationKind
{
  gboolean is_relative;
  gboolean is_symbol;
  gboolean is_absolute;
  gboolean is_tls_module;
  gboolean is_tls_offset;
  gboolean is_tls_desc;
  gboolean has_addend;
  guint64 dtp_offset;
};

struct _GumElfIndirectBinding
{
  GumAddress resolver;
  GArray * slots;
};

struct _GumElfMipsGot
{
  GumElfMapper * mapper;
  GumAddress address;
  guint local_count;
  guint first_global_symbol;
  guint symbol_index;
};

struct _GumElfIndirectSlot
{
  GumAddress address;
  GumAddress addend;
};

static void gum_elf_mapper_initable_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_elf_mapper_iface_init (gpointer g_iface, gpointer iface_data);
static void gum_elf_mapper_dispose (GObject * object);
static void gum_elf_mapper_finalize (GObject * object);
static void gum_elf_mapper_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_elf_mapper_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);

static gboolean gum_elf_mapper_initable_init (GInitable * initable,
    GCancellable * cancellable, GError ** error);
static void gum_elf_mapper_set_target (GumMapper * mapper,
    GumProcessMemory * target);
static gboolean gum_elf_mapper_map (GumMapper * mapper, gsize extra_size,
    GumAddress * extra_address, GError ** error);
static void gum_elf_mapper_unmap (GumMapper * mapper);
static const GumMemoryRange * gum_elf_mapper_get_range (GumMapper * mapper);
static GumAddress gum_elf_mapper_constructor (GumMapper * mapper);
static GumAddress gum_elf_mapper_destructor (GumMapper * mapper);
static GumAddress gum_elf_mapper_resolve (GumMapper * mapper,
    const gchar * symbol);
static void gum_elf_mapper_enumerate_exports (GumMapper * mapper,
    GumFoundExportFunc func, gpointer user_data);
static void gum_elf_mapper_init_footprint_budget (GumElfMapper * self);
static gboolean gum_collect_init_fini_counts (
    const GumElfDynamicEntryDetails * details, gpointer user_data);
static gboolean gum_collect_tls_section (const GumElfSectionDetails * details,
    gpointer user_data);
static gboolean gum_count_indirect_relocation (
    const GumElfRelocationDetails * details, gpointer user_data);
static void gum_elf_mapper_count_indirect_mips_got_entries (
    GumElfMapper * self);
static gboolean gum_count_indirect_mips_got_entry (
    const GumElfSymbolDetails * details, gpointer user_data);
static void gum_elf_mapper_read_hwcaps (GumElfMapper * self);
static void gum_elf_mapper_resolve_tls_api (GumElfMapper * self);
static gboolean gum_copy_segment (const GumElfSegmentDetails * details,
    gpointer user_data);
static gboolean gum_apply_relocation (const GumElfRelocationDetails * details,
    gpointer user_data);
static void gum_elf_mapper_classify_relocation (GumElfMapper * self,
    const GumElfRelocationDetails * details, GumElfRelocationKind * kind);
static gboolean gum_apply_relative_relocations (
    const GumElfSectionDetails * details, gpointer user_data);
static void gum_elf_mapper_apply_relative_relocation (GumElfMapper * self,
    GumAddress address);
static void gum_elf_mapper_fill_mips_got (GumElfMapper * self);
static gboolean gum_collect_mips_got_layout (
    const GumElfDynamicEntryDetails * details, gpointer user_data);
static gboolean gum_fill_mips_got_entry (const GumElfSymbolDetails * details,
    gpointer user_data);
static GumAddress gum_elf_mapper_resolve_symbol (GumElfMapper * self,
    const GumElfSymbolDetails * symbol, GumElfIndirectBinding ** binding);
static const GumDynamicSymbolDetails * gum_elf_mapper_lookup_dynamic_symbol (
    GumElfMapper * self, const gchar * name);
static GumElfIndirectBinding * gum_elf_mapper_get_indirect_binding (
    GumElfMapper * self, GumAddress resolver);
static void gum_elf_mapper_add_indirect_slot (GumElfMapper * self,
    GumElfIndirectBinding * binding, GumAddress address, GumAddress addend);
static void gum_elf_indirect_binding_free (GumElfIndirectBinding * binding);
static void gum_elf_mapper_write_staged_pointer (GumElfMapper * self,
    GumAddress address, GumAddress value);
static gboolean gum_collect_init_fini (
    const GumElfDynamicEntryDetails * details, gpointer user_data);
static void gum_elf_mapper_read_function_vector (GumElfMapper * self,
    GArray * functions, GumAddress array, gsize size, gboolean reversed);
static void gum_elf_mapper_alloc_and_emit_runtime (GumElfMapper * self);
static void gum_emit_runtime (GumElfMapper * self, gpointer output_buffer,
    GumAddress pc, gsize * size);
#if defined (HAVE_I386)
static void gum_emit_indirect_bindings (GumElfMapper * self, GumX86Writer * cw);
static void gum_emit_tls_get_addr (GumElfMapper * self, GumX86Writer * cw);
static void gum_emit_tls_key_load (GumElfMapper * self, GumX86Writer * cw);
#elif defined (HAVE_ARM)
static void gum_emit_indirect_bindings (GumElfMapper * self, GumArmWriter * cw);
static void gum_emit_tls_get_addr (GumElfMapper * self, GumArmWriter * cw);
static void gum_emit_tls_key_load (GumElfMapper * self, GumArmWriter * cw);
#elif defined (HAVE_ARM64)
static void gum_emit_indirect_bindings (GumElfMapper * self,
    GumArm64Writer * cw);
static void gum_emit_tls_get_addr (GumElfMapper * self, GumArm64Writer * cw);
static void gum_emit_tls_desc_resolver (GumElfMapper * self,
    GumArm64Writer * cw);
static void gum_emit_tls_key_load (GumElfMapper * self, GumArm64Writer * cw);
#elif defined (HAVE_MIPS)
static void gum_emit_indirect_bindings (GumElfMapper * self,
    GumMipsWriter * cw);
static void gum_emit_tls_get_addr (GumElfMapper * self, GumMipsWriter * cw);
static void gum_emit_tls_key_load (GumElfMapper * self, GumMipsWriter * cw);
#endif
static void gum_elf_mapper_bind_tls_descriptors (GumElfMapper * self);
static gboolean gum_commit_segment (const GumElfSegmentDetails * details,
    gpointer user_data);
static gboolean gum_store_export (const GumExportDetails * details,
    gpointer user_data);
static gboolean gum_elf_mapper_has_tls (GumElfMapper * self);

static GumCpuType gum_cpu_type_from_elf (GumElfMachine machine);

G_DEFINE_TYPE_WITH_CODE (GumElfMapper,
                         gum_elf_mapper,
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                             gum_elf_mapper_initable_iface_init)
                         G_IMPLEMENT_INTERFACE (GUM_TYPE_MAPPER,
                             gum_elf_mapper_iface_init))

static void
gum_elf_mapper_class_init (GumElfMapperClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_elf_mapper_dispose;
  object_class->finalize = gum_elf_mapper_finalize;
  object_class->get_property = gum_elf_mapper_get_property;
  object_class->set_property = gum_elf_mapper_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PATH,
      g_param_spec_string ("path", "Path", "Path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BLOB,
      g_param_spec_boxed ("blob", "Blob", "Blob", G_TYPE_BYTES,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_RESOLVER,
      g_param_spec_object ("resolver", "Resolver", "Module resolver",
      GUM_TYPE_MODULE_RESOLVER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
}

static void
gum_elf_mapper_initable_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  GInitableIface * iface = g_iface;

  iface->init = gum_elf_mapper_initable_init;
}

static void
gum_elf_mapper_iface_init (gpointer g_iface,
                           gpointer iface_data)
{
  GumMapperInterface * iface = g_iface;

  iface->set_target = gum_elf_mapper_set_target;
  iface->map = gum_elf_mapper_map;
  iface->unmap = gum_elf_mapper_unmap;
  iface->get_range = gum_elf_mapper_get_range;
  iface->constructor = gum_elf_mapper_constructor;
  iface->destructor = gum_elf_mapper_destructor;
  iface->resolve = gum_elf_mapper_resolve;
  iface->enumerate_exports = gum_elf_mapper_enumerate_exports;
}

static void
gum_elf_mapper_init (GumElfMapper * self)
{
  self->init_functions = g_array_new (FALSE, FALSE, sizeof (GumAddress));
  self->fini_functions = g_array_new (FALSE, FALSE, sizeof (GumAddress));
  self->tls_desc_slots = g_array_new (FALSE, FALSE, sizeof (GumAddress));
  self->symbols = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
  self->indirect_bindings = g_ptr_array_new_with_free_func (
      (GDestroyNotify) gum_elf_indirect_binding_free);
  self->indirect_binding_by_resolver =
      g_hash_table_new (g_int64_hash, g_int64_equal);
  self->target =
      GUM_PROCESS_MEMORY (gum_native_process_memory_new_local ());
}

static void
gum_elf_mapper_dispose (GObject * object)
{
  GumElfMapper * self = GUM_ELF_MAPPER (object);

  g_clear_object (&self->target);
  g_clear_object (&self->resolver);
  g_clear_object (&self->module);

  G_OBJECT_CLASS (gum_elf_mapper_parent_class)->dispose (object);
}

static void
gum_elf_mapper_finalize (GObject * object)
{
  GumElfMapper * self = GUM_ELF_MAPPER (object);

  g_hash_table_unref (self->indirect_binding_by_resolver);
  g_ptr_array_unref (self->indirect_bindings);
  g_hash_table_unref (self->symbols);
  g_array_unref (self->tls_desc_slots);
  g_array_unref (self->fini_functions);
  g_array_unref (self->init_functions);
  g_free (self->staging);
  g_free (self->runtime);
  g_clear_pointer (&self->blob, g_bytes_unref);
  g_free (self->path);
  g_free (self->name);

  G_OBJECT_CLASS (gum_elf_mapper_parent_class)->finalize (object);
}

static void
gum_elf_mapper_get_property (GObject * object,
                             guint property_id,
                             GValue * value,
                             GParamSpec * pspec)
{
  GumElfMapper * self = GUM_ELF_MAPPER (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_PATH:
      g_value_set_string (value, self->path);
      break;
    case PROP_BLOB:
      g_value_set_boxed (value, self->blob);
      break;
    case PROP_RESOLVER:
      g_value_set_object (value, self->resolver);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_elf_mapper_set_property (GObject * object,
                             guint property_id,
                             const GValue * value,
                             GParamSpec * pspec)
{
  GumElfMapper * self = GUM_ELF_MAPPER (object);

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
    case PROP_BLOB:
      g_clear_pointer (&self->blob, g_bytes_unref);
      self->blob = g_value_dup_boxed (value);
      break;
    case PROP_RESOLVER:
      g_clear_object (&self->resolver);
      self->resolver = g_value_dup_object (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumMapper *
gum_mapper_new_from_file (const gchar * path,
                          GumModuleResolver * resolver,
                          GError ** error)
{
  return g_initable_new (GUM_TYPE_ELF_MAPPER, NULL, error,
      "name", path,
      "path", path,
      "resolver", resolver,
      NULL);
}

GumMapper *
gum_mapper_new_take_blob (const gchar * name,
                          GBytes * blob,
                          GumModuleResolver * resolver,
                          GError ** error)
{
  GumMapper * mapper;

  mapper = g_initable_new (GUM_TYPE_ELF_MAPPER, NULL, error,
      "name", name,
      "blob", blob,
      "resolver", resolver,
      NULL);
  g_bytes_unref (blob);

  return mapper;
}

static gboolean
gum_elf_mapper_initable_init (GInitable * initable,
                              GCancellable * cancellable,
                              GError ** error)
{
  GumElfMapper * self = GUM_ELF_MAPPER (initable);

  self->module = (self->path != NULL)
      ? gum_elf_module_new_from_file (self->path, error)
      : gum_elf_module_new_from_blob (self->blob, error);
  if (self->module == NULL)
    return FALSE;

  self->machine = gum_elf_module_get_machine (self->module);
  self->cpu_type = gum_cpu_type_from_elf (self->machine);
  self->pointer_size = gum_elf_module_get_pointer_size (self->module);
  self->preferred_address = gum_elf_module_get_preferred_address (self->module);

  return TRUE;
}

static void
gum_elf_mapper_set_target (GumMapper * mapper,
                           GumProcessMemory * target)
{
  GumElfMapper * self = GUM_ELF_MAPPER (mapper);

  g_set_object (&self->target, target);
}

static gboolean
gum_elf_mapper_map (GumMapper * mapper,
                    gsize extra_size,
                    GumAddress * extra_address,
                    GError ** error)
{
  GumElfMapper * self = GUM_ELF_MAPPER (mapper);
  GumElfModule * module = self->module;
  gsize image_vm_size, extra_vm_size;
  GumAddress base_address;
  GumElfInitFini layout = { 0, };

  gum_elf_mapper_init_footprint_budget (self);

  image_vm_size = self->vm_size - self->runtime_vm_size;
  extra_vm_size = GUM_ALIGN_SIZE (extra_size, gum_query_page_size ());

  base_address = gum_process_memory_alloc (self->target,
      self->vm_size + extra_vm_size, gum_query_page_size ());
  if (base_address == 0)
    goto alloc_failed;
  self->range.base_address = base_address;
  self->range.size = self->vm_size + extra_vm_size;

  self->image_address = base_address;
  self->runtime_address = base_address + image_vm_size;
  if (extra_address != NULL)
    *extra_address = self->runtime_address + self->runtime_vm_size;

  self->load_bias = self->image_address - self->preferred_address;
  self->staging = g_malloc0 (self->vm_size);

  if (gum_elf_mapper_has_tls (self))
  {
    self->tls_get_addr = self->runtime_address;
    self->tls_key = self->runtime_address + self->runtime_code_size;
    self->tls_memcpy = self->tls_key + self->pointer_size;
    self->tls_template = self->image_address + self->tls.template_rva;
    gum_elf_mapper_resolve_tls_api (self);
  }

  g_object_set (module, "base-address", self->image_address, NULL);

  gum_elf_module_enumerate_segments (module, gum_copy_segment, self);

  gum_elf_module_enumerate_relocations (module, gum_apply_relocation, self);
  gum_elf_module_enumerate_sections (module, gum_apply_relative_relocations,
      self);
  if (self->machine == GUM_ELF_MACHINE_MIPS)
    gum_elf_mapper_fill_mips_got (self);
  if (self->unresolved_symbol != NULL)
    goto unresolved_symbol;

  layout.mapper = self;
  gum_elf_module_enumerate_dynamic_entries (module, gum_collect_init_fini,
      &layout);

  if (layout.init_function != 0)
  {
    GumAddress f = layout.init_function + self->load_bias;
    g_array_append_val (self->init_functions, f);
  }
  gum_elf_mapper_read_function_vector (self, self->init_functions,
      layout.init_array + self->load_bias, layout.init_array_size, FALSE);

  gum_elf_mapper_read_function_vector (self, self->fini_functions,
      layout.fini_array + self->load_bias, layout.fini_array_size, TRUE);
  if (layout.fini_function != 0)
  {
    GumAddress f = layout.fini_function + self->load_bias;
    g_array_append_val (self->fini_functions, f);
  }

  gum_elf_mapper_alloc_and_emit_runtime (self);
  gum_elf_mapper_bind_tls_descriptors (self);

  memcpy (GUM_ELF_STAGED (self, self->runtime_address), self->runtime,
      self->runtime_file_size);

  gum_process_memory_write (self->target, self->runtime_address,
      GUM_ELF_STAGED (self, self->runtime_address), self->runtime_vm_size);

  gum_elf_module_enumerate_segments (module, gum_commit_segment, self);

  gum_process_memory_mark_code (self->target, self->runtime_address,
      self->runtime_code_size);

  g_clear_pointer (&self->staging, g_free);

  return TRUE;

alloc_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
        "Unable to allocate target memory");
    return FALSE;
  }
unresolved_symbol:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
        "Unable to resolve “%s”", self->unresolved_symbol);
    g_clear_pointer (&self->staging, g_free);
    gum_elf_mapper_unmap (GUM_MAPPER (self));
    return FALSE;
  }
}

static void
gum_elf_mapper_unmap (GumMapper * mapper)
{
  GumElfMapper * self = GUM_ELF_MAPPER (mapper);

  gum_process_memory_free (self->target, self->range.base_address,
      self->range.size);
  self->range.base_address = 0;
  self->range.size = 0;
}

static const GumMemoryRange *
gum_elf_mapper_get_range (GumMapper * mapper)
{
  GumElfMapper * self = GUM_ELF_MAPPER (mapper);

  return &self->range;
}

static GumAddress
gum_elf_mapper_constructor (GumMapper * mapper)
{
  GumElfMapper * self = GUM_ELF_MAPPER (mapper);

  return self->runtime_address + self->constructor_offset;
}

static GumAddress
gum_elf_mapper_destructor (GumMapper * mapper)
{
  GumElfMapper * self = GUM_ELF_MAPPER (mapper);

  return self->runtime_address + self->destructor_offset;
}

static GumAddress
gum_elf_mapper_resolve (GumMapper * mapper,
                        const gchar * symbol)
{
  GumElfMapper * self = GUM_ELF_MAPPER (mapper);
  GumExportDetails details = { 0, };

  details.name = symbol;
  gum_elf_module_enumerate_exports (self->module, gum_store_export, &details);

  return details.address;
}

static void
gum_elf_mapper_enumerate_exports (GumMapper * mapper,
                                  GumFoundExportFunc func,
                                  gpointer user_data)
{
  GumElfMapper * self = GUM_ELF_MAPPER (mapper);

  gum_elf_module_enumerate_exports (self->module, func, user_data);
}

static void
gum_elf_mapper_init_footprint_budget (GumElfMapper * self)
{
  guint page_size = gum_query_page_size ();
  gsize image_vm_size;
  GumElfInitFini counts = { 0, };
  gboolean has_tls;
  gsize runtime_size;

  image_vm_size = GUM_ALIGN_SIZE (
      gum_elf_module_get_mapped_size (self->module), page_size);

  counts.mapper = self;
  gum_elf_module_enumerate_dynamic_entries (self->module,
      gum_collect_init_fini_counts, &counts);

  self->init_count = (counts.init_function != 0 ? 1 : 0) +
      (counts.init_array_size / self->pointer_size);
  self->fini_count = (counts.fini_function != 0 ? 1 : 0) +
      (counts.fini_array_size / self->pointer_size);

  gum_elf_module_enumerate_sections (self->module, gum_collect_tls_section,
      self);
  has_tls = gum_elf_mapper_has_tls (self);

  g_hash_table_remove_all (self->indirect_binding_by_resolver);
  g_ptr_array_set_size (self->indirect_bindings, 0);
  g_hash_table_remove_all (self->symbols);
  self->indirect_slot_count = 0;

  gum_elf_module_enumerate_relocations (self->module,
      gum_count_indirect_relocation, self);
  if (self->machine == GUM_ELF_MACHINE_MIPS)
    gum_elf_mapper_count_indirect_mips_got_entries (self);
  if (has_tls)
  {
    self->tls_api.memcpy =
        gum_elf_mapper_lookup_dynamic_symbol (self, "memcpy");
    if (self->tls_api.memcpy->indirect)
    {
      gum_elf_mapper_get_indirect_binding (self,
          self->tls_api.memcpy->address);
      self->indirect_slot_count++;
    }
  }

  runtime_size = GUM_ELF_MAPPER_CODE_BASE_SIZE +
      ((self->init_count + self->fini_count) * GUM_ELF_MAPPER_CALL_SIZE);
  if (has_tls)
    runtime_size += GUM_ELF_MAPPER_TLS_CODE_SIZE;
  if (self->indirect_bindings->len != 0)
  {
    runtime_size += GUM_ELF_MAPPER_INDIRECT_BASE_SIZE +
        (self->indirect_bindings->len * GUM_ELF_MAPPER_CALL_SIZE) +
        (self->indirect_slot_count * GUM_ELF_MAPPER_INDIRECT_STORE_SIZE);

    gum_elf_mapper_read_hwcaps (self);
  }

  self->runtime_file_size = runtime_size;
  self->runtime_code_size = GUM_ALIGN_SIZE (runtime_size, page_size);
  self->runtime_vm_size = self->runtime_code_size;
  if (has_tls)
    self->runtime_vm_size += page_size;

  self->vm_size = image_vm_size + self->runtime_vm_size;
}

static gboolean
gum_collect_init_fini_counts (const GumElfDynamicEntryDetails * details,
                              gpointer user_data)
{
  GumElfInitFini * ctx = user_data;

  switch (details->tag)
  {
    case GUM_ELF_DYNAMIC_INIT:
      ctx->init_function = details->val;
      break;
    case GUM_ELF_DYNAMIC_INIT_ARRAYSZ:
      ctx->init_array_size = details->val;
      break;
    case GUM_ELF_DYNAMIC_FINI:
      ctx->fini_function = details->val;
      break;
    case GUM_ELF_DYNAMIC_FINI_ARRAYSZ:
      ctx->fini_array_size = details->val;
      break;
    default:
      break;
  }

  return TRUE;
}

static gboolean
gum_collect_tls_section (const GumElfSectionDetails * details,
                         gpointer user_data)
{
  GumElfMapper * self = user_data;
  GumElfTlsLayout * layout = &self->tls;

  if ((details->flags & GUM_ELF_SECTION_FLAG_TLS) == 0)
    return TRUE;

  layout->memory_size += details->size;
  if (details->type != GUM_ELF_SECTION_NOBITS)
  {
    layout->image_size = details->size;
    layout->template_rva =
        details->address - gum_elf_module_get_base_address (self->module);
  }

  return TRUE;
}

static gboolean
gum_count_indirect_relocation (const GumElfRelocationDetails * details,
                               gpointer user_data)
{
  GumElfMapper * self = user_data;
  GumElfRelocationKind kind;
  GumElfIndirectBinding * binding;

  gum_elf_mapper_classify_relocation (self, details, &kind);
  if (!kind.is_symbol && !kind.is_absolute)
    return TRUE;

  gum_elf_mapper_resolve_symbol (self, details->symbol, &binding);
  if (binding != NULL)
    self->indirect_slot_count++;

  return TRUE;
}

static void
gum_elf_mapper_count_indirect_mips_got_entries (GumElfMapper * self)
{
  GumElfMipsGot got = { 0, };

  got.mapper = self;
  gum_elf_module_enumerate_dynamic_entries (self->module,
      gum_collect_mips_got_layout, &got);

  gum_elf_module_enumerate_dynamic_symbols (self->module,
      gum_count_indirect_mips_got_entry, &got);
}

static gboolean
gum_count_indirect_mips_got_entry (const GumElfSymbolDetails * details,
                                   gpointer user_data)
{
  GumElfMipsGot * got = user_data;
  GumElfMapper * self = got->mapper;
  GumElfIndirectBinding * binding;

  if (got->symbol_index++ < got->first_global_symbol)
    return TRUE;

  gum_elf_mapper_resolve_symbol (self, details, &binding);
  if (binding != NULL)
    self->indirect_slot_count++;

  return TRUE;
}

static void
gum_elf_mapper_read_hwcaps (GumElfMapper * self)
{
  gchar * path, * auxv;
  gsize size, offset;

  self->hwcap = 0;
  self->hwcap2 = 0;

  path = g_strdup_printf ("/proc/%u/auxv",
      gum_process_memory_get_pid (self->target));
  if (!g_file_get_contents (path, &auxv, &size, NULL))
    goto beach;

  for (offset = 0; offset + (2 * self->pointer_size) <= size;
      offset += 2 * self->pointer_size)
  {
    guint64 type, value;

    if (self->pointer_size == 8)
    {
      type = *((guint64 *) (auxv + offset));
      value = *((guint64 *) (auxv + offset + 8));
    }
    else
    {
      type = *((guint32 *) (auxv + offset));
      value = *((guint32 *) (auxv + offset + 4));
    }

    if (type == GUM_ELF_AT_NULL)
      break;
    if (type == GUM_ELF_AT_HWCAP)
      self->hwcap = value;
    else if (type == GUM_ELF_AT_HWCAP2)
      self->hwcap2 = value;
  }

  g_free (auxv);

beach:
  g_free (path);
}

static void
gum_elf_mapper_resolve_tls_api (GumElfMapper * self)
{
  GumModuleResolver * resolver = self->resolver;
  GumElfTlsApi * api = &self->tls_api;

  api->key_create =
      gum_module_resolver_find_dynamic_address (resolver, "pthread_key_create");
  api->key_delete =
      gum_module_resolver_find_dynamic_address (resolver, "pthread_key_delete");
  api->getspecific = gum_module_resolver_find_dynamic_address (resolver,
      "pthread_getspecific");
  api->setspecific = gum_module_resolver_find_dynamic_address (resolver,
      "pthread_setspecific");
  api->calloc = gum_module_resolver_find_dynamic_address (resolver, "calloc");
  api->free = gum_module_resolver_find_dynamic_address (resolver, "free");

  if (api->memcpy->indirect)
  {
    gum_elf_mapper_add_indirect_slot (self,
        gum_elf_mapper_get_indirect_binding (self, api->memcpy->address),
        self->tls_memcpy, 0);
  }
  else
  {
    gum_elf_mapper_write_staged_pointer (self, self->tls_memcpy,
        api->memcpy->address);
  }
}

static gboolean
gum_copy_segment (const GumElfSegmentDetails * details,
                  gpointer user_data)
{
  GumElfMapper * self = user_data;
  gsize file_size;
  gconstpointer file_data;
  guint8 * dst = GUM_ELF_STAGED (self, details->vm_address + self->load_bias);

  if (details->file_size == 0)
    return TRUE;

  file_data = gum_elf_module_get_file_data (self->module, &file_size);
  memcpy (dst, (const guint8 *) file_data + details->file_offset,
      details->file_size);

  return TRUE;
}

static gboolean
gum_apply_relocation (const GumElfRelocationDetails * details,
                      gpointer user_data)
{
  GumElfMapper * self = user_data;
  guint8 * target = GUM_ELF_STAGED (self, details->address);
  GumElfRelocationKind kind;
  GumAddress sym;
  GumElfIndirectBinding * binding;
  guint64 current, addend, value;

  gum_elf_mapper_classify_relocation (self, details, &kind);

  sym = gum_elf_mapper_resolve_symbol (self, details->symbol, &binding);

  current = (self->pointer_size == 8)
      ? *((guint64 *) target)
      : *((guint32 *) target);

  if (kind.has_addend)
    addend = details->addend;
  else if (kind.is_symbol)
    addend = 0;
  else
    addend = current;

  if (binding != NULL && (kind.is_symbol || kind.is_absolute))
  {
    gum_elf_mapper_add_indirect_slot (self, binding, details->address,
        addend);
    return TRUE;
  }

  if (kind.is_relative)
    value = self->load_bias + addend;
  else if (kind.is_symbol || kind.is_absolute)
    value = sym + addend;
  else if (kind.is_tls_offset)
    value = sym + addend - kind.dtp_offset;
  else if (kind.is_tls_module)
    value = GUM_ELF_TLS_MODULE_ID;
  else if (kind.is_tls_desc)
  {
    ((guint64 *) target)[1] = sym + addend;
    g_array_append_val (self->tls_desc_slots, details->address);
    return TRUE;
  }
  else
    return TRUE;

  if (self->pointer_size == 8)
    *((guint64 *) target) = value;
  else
    *((guint32 *) target) = value;

  return TRUE;
}

static void
gum_elf_mapper_classify_relocation (GumElfMapper * self,
                                    const GumElfRelocationDetails * details,
                                    GumElfRelocationKind * kind)
{
  guint32 type = details->type;

  memset (kind, 0, sizeof (GumElfRelocationKind));

  switch (self->machine)
  {
    case GUM_ELF_MACHINE_386:
      kind->is_relative = type == GUM_ELF_R_386_RELATIVE;
      kind->is_symbol = type == GUM_ELF_R_386_GLOB_DAT ||
          type == GUM_ELF_R_386_JMP_SLOT;
      kind->is_absolute = type == GUM_ELF_R_386_32;
      kind->is_tls_module = type == GUM_ELF_R_386_TLS_DTPMOD32;
      kind->is_tls_offset = type == GUM_ELF_R_386_TLS_DTPOFF32;
      break;
    case GUM_ELF_MACHINE_X86_64:
      kind->is_relative = type == GUM_ELF_R_X86_64_RELATIVE;
      kind->is_symbol = type == GUM_ELF_R_X86_64_GLOB_DAT ||
          type == GUM_ELF_R_X86_64_JUMP_SLOT;
      kind->is_absolute = type == GUM_ELF_R_X86_64_64;
      kind->is_tls_module = type == GUM_ELF_R_X86_64_DTPMOD64;
      kind->is_tls_offset = type == GUM_ELF_R_X86_64_DTPOFF64;
      kind->has_addend = TRUE;
      break;
    case GUM_ELF_MACHINE_ARM:
      kind->is_relative = type == GUM_ELF_R_ARM_RELATIVE;
      kind->is_symbol = type == GUM_ELF_R_ARM_GLOB_DAT ||
          type == GUM_ELF_R_ARM_JUMP_SLOT;
      kind->is_absolute = type == GUM_ELF_R_ARM_ABS32;
      kind->is_tls_module = type == GUM_ELF_R_ARM_TLS_DTPMOD32;
      kind->is_tls_offset = type == GUM_ELF_R_ARM_TLS_DTPOFF32;
      break;
    case GUM_ELF_MACHINE_AARCH64:
      kind->is_relative = type == GUM_ELF_R_AARCH64_RELATIVE;
      kind->is_symbol = type == GUM_ELF_R_AARCH64_GLOB_DAT ||
          type == GUM_ELF_R_AARCH64_JUMP_SLOT;
      kind->is_absolute = type == GUM_ELF_R_AARCH64_ABS64;
      kind->is_tls_module = type == GUM_ELF_R_AARCH64_TLS_DTPMOD;
      kind->is_tls_offset = type == GUM_ELF_R_AARCH64_TLS_DTPREL;
      kind->is_tls_desc = type == GUM_ELF_R_AARCH64_TLSDESC;
      kind->has_addend = TRUE;
      break;
    case GUM_ELF_MACHINE_MIPS:
      type &= 0xff;
      kind->is_relative =
          type == GUM_ELF_R_MIPS_REL32 && details->symbol == NULL;
      kind->is_symbol = type == GUM_ELF_R_MIPS_GLOB_DAT ||
          type == GUM_ELF_R_MIPS_JUMP_SLOT;
      kind->is_absolute =
          (type == GUM_ELF_R_MIPS_REL32 && details->symbol != NULL) ||
          type == GUM_ELF_R_MIPS_32 || type == GUM_ELF_R_MIPS_64;
      kind->is_tls_module = type == GUM_ELF_R_MIPS_TLS_DTPMOD32 ||
          type == GUM_ELF_R_MIPS_TLS_DTPMOD64;
      kind->is_tls_offset = type == GUM_ELF_R_MIPS_TLS_DTPREL32 ||
          type == GUM_ELF_R_MIPS_TLS_DTPREL64;
      kind->dtp_offset = GUM_ELF_MIPS_DTP_OFFSET;
      break;
    default:
      break;
  }
}

static gboolean
gum_apply_relative_relocations (const GumElfSectionDetails * details,
                                gpointer user_data)
{
  GumElfMapper * self = user_data;
  gsize file_size;
  gconstpointer file_data;
  const guint8 * entries;
  guint pointer_size = self->pointer_size;
  guint count, i;
  GumAddress where = 0;
  guint bitmap_width = (pointer_size * 8) - 1;

  if (details->type != GUM_ELF_SECTION_RELR &&
      details->type != GUM_ELF_SECTION_ANDROID_RELR)
  {
    return TRUE;
  }

  file_data = gum_elf_module_get_file_data (self->module, &file_size);
  entries = (const guint8 *) file_data + details->offset;
  count = details->size / pointer_size;

  for (i = 0; i != count; i++)
  {
    guint64 entry = (pointer_size == 8)
        ? ((const guint64 *) entries)[i]
        : ((const guint32 *) entries)[i];

    if ((entry & 1) == 0)
    {
      where = entry;
      gum_elf_mapper_apply_relative_relocation (self, where);
      where += pointer_size;
    }
    else
    {
      guint bit;

      for (bit = 0; bit != bitmap_width; bit++)
      {
        if (((entry >> (bit + 1)) & 1) != 0)
        {
          gum_elf_mapper_apply_relative_relocation (self,
              where + (bit * pointer_size));
        }
      }
      where += bitmap_width * pointer_size;
    }
  }

  return TRUE;
}

static void
gum_elf_mapper_apply_relative_relocation (GumElfMapper * self,
                                          GumAddress address)
{
  guint8 * target = GUM_ELF_STAGED (self, address + self->load_bias);

  if (self->pointer_size == 8)
    *((guint64 *) target) += self->load_bias;
  else
    *((guint32 *) target) += self->load_bias;
}

static void
gum_elf_mapper_fill_mips_got (GumElfMapper * self)
{
  GumElfMipsGot got = { 0, };
  guint8 * entries;
  guint first_local_entry, i;

  got.mapper = self;
  gum_elf_module_enumerate_dynamic_entries (self->module,
      gum_collect_mips_got_layout, &got);

  got.address += self->load_bias;
  entries = GUM_ELF_STAGED (self, got.address);

  if (self->pointer_size == 8)
  {
    guint64 * slots = (guint64 *) entries;

    first_local_entry =
        ((slots[1] >> 32) & GUM_ELF_MIPS_GOT1_RESERVED_MASK) != 0 ? 2 : 1;
    for (i = first_local_entry; i != got.local_count; i++)
      slots[i] += self->load_bias;
  }
  else
  {
    guint32 * slots = (guint32 *) entries;

    first_local_entry =
        (slots[1] & GUM_ELF_MIPS_GOT1_RESERVED_MASK) != 0 ? 2 : 1;
    for (i = first_local_entry; i != got.local_count; i++)
      slots[i] += self->load_bias;
  }

  got.symbol_index = 1;
  gum_elf_module_enumerate_dynamic_symbols (self->module,
      gum_fill_mips_got_entry, &got);
}

static gboolean
gum_collect_mips_got_layout (const GumElfDynamicEntryDetails * details,
                             gpointer user_data)
{
  GumElfMipsGot * got = user_data;

  switch (details->tag)
  {
    case GUM_ELF_DYNAMIC_PLTGOT:
      got->address = details->val;
      break;
    case GUM_ELF_DYNAMIC_MIPS_LOCAL_GOTNO:
      got->local_count = details->val;
      break;
    case GUM_ELF_DYNAMIC_MIPS_GOTSYM:
      got->first_global_symbol = details->val;
      break;
    default:
      break;
  }

  return TRUE;
}

static gboolean
gum_fill_mips_got_entry (const GumElfSymbolDetails * details,
                         gpointer user_data)
{
  GumElfMipsGot * got = user_data;
  guint index = got->symbol_index++;
  GumElfMapper * self = got->mapper;
  GumAddress slot, address;
  GumElfIndirectBinding * binding;

  if (index < got->first_global_symbol)
    return TRUE;

  slot = got->address +
      ((got->local_count + index - got->first_global_symbol) *
        self->pointer_size);

  address = gum_elf_mapper_resolve_symbol (self, details, &binding);
  if (binding != NULL)
    gum_elf_mapper_add_indirect_slot (self, binding, slot, 0);
  else
    gum_elf_mapper_write_staged_pointer (self, slot, address);

  return TRUE;
}

static GumAddress
gum_elf_mapper_resolve_symbol (GumElfMapper * self,
                               const GumElfSymbolDetails * symbol,
                               GumElfIndirectBinding ** binding)
{
  const gchar * tls_get_addr_name;
  const GumDynamicSymbolDetails * details;

  *binding = NULL;

  if (symbol == NULL)
    return 0;

  if (symbol->shdr_index != GUM_ELF_SHN_UNDEF)
    return symbol->address;

  tls_get_addr_name = (self->machine == GUM_ELF_MACHINE_386)
      ? "___tls_get_addr"
      : "__tls_get_addr";
  if (strcmp (symbol->name, tls_get_addr_name) == 0)
    return self->tls_get_addr;

  details = gum_elf_mapper_lookup_dynamic_symbol (self, symbol->name);
  if (details->address == 0 && symbol->bind != GUM_ELF_BIND_WEAK)
    self->unresolved_symbol = symbol->name;

  if (details->indirect)
    *binding = gum_elf_mapper_get_indirect_binding (self, details->address);

  return details->address;
}

static const GumDynamicSymbolDetails *
gum_elf_mapper_lookup_dynamic_symbol (GumElfMapper * self,
                                      const gchar * name)
{
  GumDynamicSymbolDetails * details;

  details = g_hash_table_lookup (self->symbols, name);
  if (details == NULL)
  {
    details = g_new0 (GumDynamicSymbolDetails, 1);
    gum_module_resolver_find_dynamic_symbol (self->resolver, name, details);
    g_hash_table_insert (self->symbols, (gpointer) name, details);
  }

  return details;
}

static GumElfIndirectBinding *
gum_elf_mapper_get_indirect_binding (GumElfMapper * self,
                                     GumAddress resolver)
{
  GumElfIndirectBinding * binding;

  binding = g_hash_table_lookup (self->indirect_binding_by_resolver,
      &resolver);
  if (binding == NULL)
  {
    binding = g_slice_new (GumElfIndirectBinding);
    binding->resolver = resolver;
    binding->slots = g_array_new (FALSE, FALSE, sizeof (GumElfIndirectSlot));

    g_ptr_array_add (self->indirect_bindings, binding);
    g_hash_table_insert (self->indirect_binding_by_resolver,
        &binding->resolver, binding);
  }

  return binding;
}

static void
gum_elf_mapper_add_indirect_slot (GumElfMapper * self,
                                  GumElfIndirectBinding * binding,
                                  GumAddress address,
                                  GumAddress addend)
{
  GumElfIndirectSlot slot;

  slot.address = address;
  slot.addend = addend;
  g_array_append_val (binding->slots, slot);
}

static void
gum_elf_indirect_binding_free (GumElfIndirectBinding * binding)
{
  g_array_unref (binding->slots);

  g_slice_free (GumElfIndirectBinding, binding);
}

static void
gum_elf_mapper_write_staged_pointer (GumElfMapper * self,
                                     GumAddress address,
                                     GumAddress value)
{
  guint8 * slot = GUM_ELF_STAGED (self, address);

  if (self->pointer_size == 8)
    *((guint64 *) slot) = value;
  else
    *((guint32 *) slot) = value;
}

static gboolean
gum_collect_init_fini (const GumElfDynamicEntryDetails * details,
                       gpointer user_data)
{
  GumElfInitFini * ctx = user_data;

  switch (details->tag)
  {
    case GUM_ELF_DYNAMIC_INIT:
      ctx->init_function = details->val;
      break;
    case GUM_ELF_DYNAMIC_INIT_ARRAY:
      ctx->init_array = details->val;
      break;
    case GUM_ELF_DYNAMIC_INIT_ARRAYSZ:
      ctx->init_array_size = details->val;
      break;
    case GUM_ELF_DYNAMIC_FINI:
      ctx->fini_function = details->val;
      break;
    case GUM_ELF_DYNAMIC_FINI_ARRAY:
      ctx->fini_array = details->val;
      break;
    case GUM_ELF_DYNAMIC_FINI_ARRAYSZ:
      ctx->fini_array_size = details->val;
      break;
    default:
      break;
  }

  return TRUE;
}

static void
gum_elf_mapper_read_function_vector (GumElfMapper * self,
                                     GArray * functions,
                                     GumAddress array,
                                     gsize size,
                                     gboolean reversed)
{
  guint i;
  guint count = size / self->pointer_size;
  GumAddress all_ones = (self->pointer_size == 8) ? G_MAXUINT64 : G_MAXUINT32;

  for (i = 0; i != count; i++)
  {
    guint index = reversed ? (count - 1 - i) : i;
    GumAddress slot = array + (index * self->pointer_size);
    GumAddress function = (self->pointer_size == 8)
        ? *((const guint64 *) GUM_ELF_STAGED (self, slot))
        : *((const guint32 *) GUM_ELF_STAGED (self, slot));

    if (function == 0 || function == all_ones)
      continue;

    g_array_append_val (functions, function);
  }
}

static void
gum_elf_mapper_alloc_and_emit_runtime (GumElfMapper * self)
{
  gsize code_size;

  self->runtime = g_malloc0 (self->runtime_file_size);

  gum_emit_runtime (self, self->runtime, self->runtime_address, &code_size);

  g_assert (code_size <= self->runtime_file_size);
}

#if defined (HAVE_I386)

static void
gum_emit_runtime (GumElfMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  GumX86Writer cw;
  gboolean has_tls = gum_elf_mapper_has_tls (self);
  const GumElfTlsApi * api = &self->tls_api;
  guint i;

  gum_x86_writer_init (&cw, output_buffer);
  cw.pc = pc;
  gum_x86_writer_set_target_cpu (&cw, self->cpu_type);
  gum_x86_writer_set_target_abi (&cw, GUM_ABI_UNIX);

  if (has_tls)
    gum_emit_tls_get_addr (self, &cw);

  self->constructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBP);
  gum_emit_indirect_bindings (self, &cw);
  if (has_tls)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_CAPI, api->key_create, 2,
        GUM_ARG_ADDRESS, self->tls_key,
        GUM_ARG_ADDRESS, api->free);
  }
  for (i = 0; i != self->init_functions->len; i++)
  {
    GumAddress f = g_array_index (self->init_functions, GumAddress, i);

    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_CAPI, f, 3,
        GUM_ARG_ADDRESS, (GumAddress) 0,
        GUM_ARG_ADDRESS, (GumAddress) 0,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_ret (&cw);

  self->destructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBP);
  for (i = 0; i != self->fini_functions->len; i++)
  {
    GumAddress f = g_array_index (self->fini_functions, GumAddress, i);

    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_CAPI, f, 0);
  }
  if (has_tls)
  {
    gum_emit_tls_key_load (self, &cw);
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_CAPI, api->getspecific, 1,
        GUM_ARG_REGISTER, GUM_X86_EAX);
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_CAPI, api->free, 1,
        GUM_ARG_REGISTER, GUM_X86_XAX);
    gum_emit_tls_key_load (self, &cw);
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw,
        GUM_CALL_CAPI, api->key_delete, 1,
        GUM_ARG_REGISTER, GUM_X86_EAX);
  }
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  *size = gum_x86_writer_offset (&cw);
  gum_x86_writer_clear (&cw);
}

static void
gum_emit_indirect_bindings (GumElfMapper * self,
                            GumX86Writer * cw)
{
  guint i, j;

  for (i = 0; i != self->indirect_bindings->len; i++)
  {
    GumElfIndirectBinding * binding =
        g_ptr_array_index (self->indirect_bindings, i);

    gum_x86_writer_put_call_address_with_aligned_arguments (cw,
        GUM_CALL_CAPI, binding->resolver, 0);

    for (j = 0; j != binding->slots->len; j++)
    {
      GumElfIndirectSlot * slot =
          &g_array_index (binding->slots, GumElfIndirectSlot, j);

      gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX, slot->address);
      gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XDX, GUM_X86_XAX,
          slot->addend);
      gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XCX, 0,
          GUM_X86_XDX);
    }
  }
}

static void
gum_emit_tls_get_addr (GumElfMapper * self,
                       GumX86Writer * cw)
{
  GumX86Reg index_reg = GUM_X86_XBX;
  gboolean is_ia32 = self->cpu_type == GUM_CPU_IA32;
  GumX86Reg block_reg = is_ia32 ? GUM_X86_XSI : GUM_X86_R12;
  const GumElfTlsApi * api = &self->tls_api;
  gconstpointer have_block = cw->code + 1;

  gum_x86_writer_put_push_reg (cw, GUM_X86_XBP);
  gum_x86_writer_put_push_reg (cw, index_reg);
  gum_x86_writer_put_push_reg (cw, block_reg);
  gum_x86_writer_put_mov_reg_reg (cw, index_reg,
      is_ia32 ? GUM_X86_XAX : GUM_X86_XDI);

  gum_emit_tls_key_load (self, cw);
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_CAPI, api->getspecific, 1,
      GUM_ARG_REGISTER, GUM_X86_EAX);
  gum_x86_writer_put_test_reg_reg (cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JNE, have_block, GUM_NO_HINT);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_CAPI, api->calloc, 2,
      GUM_ARG_ADDRESS, (GumAddress) 1,
      GUM_ARG_ADDRESS, (GumAddress) self->tls.memory_size);
  gum_x86_writer_put_mov_reg_reg (cw, block_reg, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_XAX, self->tls_memcpy);
  gum_x86_writer_put_call_reg_with_aligned_arguments (cw,
      GUM_CALL_CAPI, GUM_X86_XAX, 3,
      GUM_ARG_REGISTER, block_reg,
      GUM_ARG_ADDRESS, self->tls_template,
      GUM_ARG_ADDRESS, (GumAddress) self->tls.image_size);
  gum_emit_tls_key_load (self, cw);
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_CAPI, api->setspecific, 2,
      GUM_ARG_REGISTER, GUM_X86_EAX,
      GUM_ARG_REGISTER, block_reg);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XAX, block_reg);

  gum_x86_writer_put_label (cw, have_block);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XCX, index_reg,
      self->pointer_size);
  gum_x86_writer_put_add_reg_reg (cw, GUM_X86_XAX, GUM_X86_XCX);

  gum_x86_writer_put_pop_reg (cw, block_reg);
  gum_x86_writer_put_pop_reg (cw, index_reg);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XBP);
  gum_x86_writer_put_ret (cw);
}

static void
gum_emit_tls_key_load (GumElfMapper * self,
                       GumX86Writer * cw)
{
  gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_EAX, self->tls_key);
}

#elif defined (HAVE_ARM)

static void
gum_emit_runtime (GumElfMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  GumArmWriter cw;
  gboolean has_tls = gum_elf_mapper_has_tls (self);
  const GumElfTlsApi * api = &self->tls_api;
  guint i;

  gum_arm_writer_init (&cw, output_buffer);
  cw.pc = pc;

  if (has_tls)
    gum_emit_tls_get_addr (self, &cw);

  self->constructor_offset = gum_arm_writer_offset (&cw);
  gum_arm_writer_put_push_regs (&cw, 2, ARM_REG_R11, ARM_REG_LR);
  gum_emit_indirect_bindings (self, &cw);
  if (has_tls)
  {
    gum_arm_writer_put_call_address_with_arguments (&cw, api->key_create, 2,
        GUM_ARG_ADDRESS, self->tls_key,
        GUM_ARG_ADDRESS, api->free);
  }
  for (i = 0; i != self->init_functions->len; i++)
  {
    GumAddress f = g_array_index (self->init_functions, GumAddress, i);

    gum_arm_writer_put_call_address_with_arguments (&cw, f, 3,
        GUM_ARG_ADDRESS, (GumAddress) 0,
        GUM_ARG_ADDRESS, (GumAddress) 0,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }
  gum_arm_writer_put_pop_regs (&cw, 2, ARM_REG_R11, ARM_REG_LR);
  gum_arm_writer_put_ret (&cw);

  self->destructor_offset = gum_arm_writer_offset (&cw);
  gum_arm_writer_put_push_regs (&cw, 2, ARM_REG_R11, ARM_REG_LR);
  for (i = 0; i != self->fini_functions->len; i++)
  {
    GumAddress f = g_array_index (self->fini_functions, GumAddress, i);

    gum_arm_writer_put_call_address_with_arguments (&cw, f, 0);
  }
  if (has_tls)
  {
    gum_emit_tls_key_load (self, &cw);
    gum_arm_writer_put_call_address_with_arguments (&cw, api->getspecific, 1,
        GUM_ARG_REGISTER, ARM_REG_R3);
    gum_arm_writer_put_call_address_with_arguments (&cw, api->free, 1,
        GUM_ARG_REGISTER, ARM_REG_R0);
    gum_emit_tls_key_load (self, &cw);
    gum_arm_writer_put_call_address_with_arguments (&cw, api->key_delete, 1,
        GUM_ARG_REGISTER, ARM_REG_R3);
  }
  gum_arm_writer_put_pop_regs (&cw, 2, ARM_REG_R11, ARM_REG_LR);
  gum_arm_writer_put_ret (&cw);

  gum_arm_writer_flush (&cw);
  *size = gum_arm_writer_offset (&cw);
  gum_arm_writer_clear (&cw);
}

static void
gum_emit_indirect_bindings (GumElfMapper * self,
                            GumArmWriter * cw)
{
  guint i, j;

  for (i = 0; i != self->indirect_bindings->len; i++)
  {
    GumElfIndirectBinding * binding =
        g_ptr_array_index (self->indirect_bindings, i);

    gum_arm_writer_put_call_address_with_arguments (cw, binding->resolver, 1,
        GUM_ARG_ADDRESS, (GumAddress) self->hwcap);

    for (j = 0; j != binding->slots->len; j++)
    {
      GumElfIndirectSlot * slot =
          &g_array_index (binding->slots, GumElfIndirectSlot, j);

      gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R1, slot->address);
      gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R2, slot->addend);
      gum_arm_writer_put_add_reg_reg_reg (cw, ARM_REG_R2, ARM_REG_R0,
          ARM_REG_R2);
      gum_arm_writer_put_str_reg_reg_offset (cw, ARM_REG_R2, ARM_REG_R1, 0);
    }
  }
}

static void
gum_emit_tls_get_addr (GumElfMapper * self,
                       GumArmWriter * cw)
{
  const arm_reg index_reg = ARM_REG_R4;
  const arm_reg block_reg = ARM_REG_R5;
  const GumElfTlsApi * api = &self->tls_api;
  gconstpointer have_block = cw->code + 1;

  gum_arm_writer_put_push_regs (cw, 4, index_reg, block_reg, ARM_REG_R11,
      ARM_REG_LR);
  gum_arm_writer_put_mov_reg_reg (cw, index_reg, ARM_REG_R0);

  gum_emit_tls_key_load (self, cw);
  gum_arm_writer_put_call_address_with_arguments (cw, api->getspecific, 1,
      GUM_ARG_REGISTER, ARM_REG_R3);
  gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R0, 0);
  gum_arm_writer_put_b_cond_label (cw, ARM_CC_NE, have_block);

  gum_arm_writer_put_call_address_with_arguments (cw, api->calloc, 2,
      GUM_ARG_ADDRESS, (GumAddress) 1,
      GUM_ARG_ADDRESS, (GumAddress) self->tls.memory_size);
  gum_arm_writer_put_mov_reg_reg (cw, block_reg, ARM_REG_R0);
  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R12, self->tls_memcpy);
  gum_arm_writer_put_ldr_reg_reg (cw, ARM_REG_R12, ARM_REG_R12);
  gum_arm_writer_put_call_reg_with_arguments (cw, ARM_REG_R12, 3,
      GUM_ARG_REGISTER, block_reg,
      GUM_ARG_ADDRESS, self->tls_template,
      GUM_ARG_ADDRESS, (GumAddress) self->tls.image_size);
  gum_emit_tls_key_load (self, cw);
  gum_arm_writer_put_call_address_with_arguments (cw, api->setspecific, 2,
      GUM_ARG_REGISTER, ARM_REG_R3,
      GUM_ARG_REGISTER, block_reg);
  gum_arm_writer_put_mov_reg_reg (cw, ARM_REG_R0, block_reg);

  gum_arm_writer_put_label (cw, have_block);
  gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R1, index_reg,
      self->pointer_size);
  gum_arm_writer_put_add_reg_reg_reg (cw, ARM_REG_R0, ARM_REG_R0, ARM_REG_R1);

  gum_arm_writer_put_pop_regs (cw, 4, index_reg, block_reg, ARM_REG_R11,
      ARM_REG_LR);
  gum_arm_writer_put_ret (cw);
}

static void
gum_emit_tls_key_load (GumElfMapper * self,
                       GumArmWriter * cw)
{
  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R3, self->tls_key);
  gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R3, ARM_REG_R3, 0);
}

#elif defined (HAVE_ARM64)

static void
gum_emit_runtime (GumElfMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  GumArm64Writer cw;
  gboolean has_tls = gum_elf_mapper_has_tls (self);
  const GumElfTlsApi * api = &self->tls_api;
  guint i;

  gum_arm64_writer_init (&cw, output_buffer);
  cw.pc = pc;

  if (has_tls)
    gum_emit_tls_get_addr (self, &cw);
  if (self->tls_desc_slots->len != 0)
    gum_emit_tls_desc_resolver (self, &cw);

  self->constructor_offset = gum_arm64_writer_offset (&cw);
  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_emit_indirect_bindings (self, &cw);
  if (has_tls)
  {
    gum_arm64_writer_put_call_address_with_arguments (&cw, api->key_create, 2,
        GUM_ARG_ADDRESS, self->tls_key,
        GUM_ARG_ADDRESS, api->free);
  }
  for (i = 0; i != self->init_functions->len; i++)
  {
    GumAddress f = g_array_index (self->init_functions, GumAddress, i);

    gum_arm64_writer_put_call_address_with_arguments (&cw, f, 3,
        GUM_ARG_ADDRESS, (GumAddress) 0,
        GUM_ARG_ADDRESS, (GumAddress) 0,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&cw);

  self->destructor_offset = gum_arm64_writer_offset (&cw);
  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  for (i = 0; i != self->fini_functions->len; i++)
  {
    GumAddress f = g_array_index (self->fini_functions, GumAddress, i);

    gum_arm64_writer_put_call_address_with_arguments (&cw, f, 0);
  }
  if (has_tls)
  {
    gum_emit_tls_key_load (self, &cw);
    gum_arm64_writer_put_call_address_with_arguments (&cw, api->getspecific, 1,
        GUM_ARG_REGISTER, ARM64_REG_W3);
    gum_arm64_writer_put_call_address_with_arguments (&cw, api->free, 1,
        GUM_ARG_REGISTER, ARM64_REG_X0);
    gum_emit_tls_key_load (self, &cw);
    gum_arm64_writer_put_call_address_with_arguments (&cw, api->key_delete, 1,
        GUM_ARG_REGISTER, ARM64_REG_W3);
  }
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_flush (&cw);
  *size = gum_arm64_writer_offset (&cw);
  gum_arm64_writer_clear (&cw);
}

static void
gum_emit_indirect_bindings (GumElfMapper * self,
                            GumArm64Writer * cw)
{
  guint i, j;

  if (self->indirect_bindings->len == 0)
    return;

  gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_SP, ARM64_REG_SP, 32);
  gum_arm64_writer_put_ldr_reg_u64 (cw, ARM64_REG_X0, 24);
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X0, ARM64_REG_SP, 0);
  gum_arm64_writer_put_ldr_reg_u64 (cw, ARM64_REG_X0, self->hwcap);
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X0, ARM64_REG_SP, 8);
  gum_arm64_writer_put_ldr_reg_u64 (cw, ARM64_REG_X0, self->hwcap2);
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X0, ARM64_REG_SP,
      16);

  for (i = 0; i != self->indirect_bindings->len; i++)
  {
    GumElfIndirectBinding * binding =
        g_ptr_array_index (self->indirect_bindings, i);

    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X1, ARM64_REG_SP, 0);
    gum_arm64_writer_put_call_address_with_arguments (cw, binding->resolver,
        2,
        GUM_ARG_ADDRESS, self->hwcap | GUM_ELF_IFUNC_ARG_HWCAP,
        GUM_ARG_REGISTER, ARM64_REG_X1);

    for (j = 0; j != binding->slots->len; j++)
    {
      GumElfIndirectSlot * slot =
          &g_array_index (binding->slots, GumElfIndirectSlot, j);

      gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X1, slot->address);
      gum_arm64_writer_put_ldr_reg_u64 (cw, ARM64_REG_X2, slot->addend);
      gum_arm64_writer_put_add_reg_reg_reg (cw, ARM64_REG_X2, ARM64_REG_X0,
          ARM64_REG_X2);
      gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X2, ARM64_REG_X1,
          0);
    }
  }

  gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_SP, ARM64_REG_SP, 32);
}

static void
gum_emit_tls_get_addr (GumElfMapper * self,
                       GumArm64Writer * cw)
{
  const arm64_reg index_reg = ARM64_REG_X19;
  const arm64_reg block_reg = ARM64_REG_X20;
  const GumElfTlsApi * api = &self->tls_api;
  gconstpointer have_block = cw->code + 1;

  gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_push_reg_reg (cw, index_reg, block_reg);
  gum_arm64_writer_put_mov_reg_reg (cw, index_reg, ARM64_REG_X0);

  gum_emit_tls_key_load (self, cw);
  gum_arm64_writer_put_call_address_with_arguments (cw, api->getspecific, 1,
      GUM_ARG_REGISTER, ARM64_REG_W3);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X0, have_block);

  gum_arm64_writer_put_call_address_with_arguments (cw, api->calloc, 2,
      GUM_ARG_ADDRESS, (GumAddress) 1,
      GUM_ARG_ADDRESS, (GumAddress) self->tls.memory_size);
  gum_arm64_writer_put_mov_reg_reg (cw, block_reg, ARM64_REG_X0);
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16, self->tls_memcpy);
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X16,
      0);
  gum_arm64_writer_put_call_reg_with_arguments (cw, ARM64_REG_X16, 3,
      GUM_ARG_REGISTER, block_reg,
      GUM_ARG_ADDRESS, self->tls_template,
      GUM_ARG_ADDRESS, (GumAddress) self->tls.image_size);
  gum_emit_tls_key_load (self, cw);
  gum_arm64_writer_put_call_address_with_arguments (cw, api->setspecific, 2,
      GUM_ARG_REGISTER, ARM64_REG_W3,
      GUM_ARG_REGISTER, block_reg);
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X0, block_reg);

  gum_arm64_writer_put_label (cw, have_block);
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X1, index_reg,
      self->pointer_size);
  gum_arm64_writer_put_add_reg_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X0,
      ARM64_REG_X1);

  gum_arm64_writer_put_pop_reg_reg (cw, index_reg, block_reg);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (cw);
}

static void
gum_emit_tls_desc_resolver (GumElfMapper * self,
                            GumArm64Writer * cw)
{
  guint i;
  const guint n_pairs = 9;

  self->tls_desc_resolver = cw->pc;

  gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_FP, ARM64_REG_LR);
  for (i = 0; i != n_pairs; i++)
  {
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X1 + (2 * i),
        ARM64_REG_X2 + (2 * i));
  }
  gum_arm64_writer_put_push_all_q_registers (cw);

  gum_arm64_writer_put_bl_imm (cw, self->tls_get_addr);
  gum_arm64_writer_put_mrs (cw, ARM64_REG_X1, GUM_ARM64_SYSREG_TPIDR_EL0);
  gum_arm64_writer_put_sub_reg_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X0,
      ARM64_REG_X1);

  gum_arm64_writer_put_pop_all_q_registers (cw);
  for (i = n_pairs; i != 0; i--)
  {
    gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X1 + (2 * (i - 1)),
        ARM64_REG_X2 + (2 * (i - 1)));
  }
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (cw);
}

static void
gum_emit_tls_key_load (GumElfMapper * self,
                       GumArm64Writer * cw)
{
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X3, self->tls_key);
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_W3, ARM64_REG_X3, 0);
}

#elif defined (HAVE_MIPS)

static void
gum_emit_runtime (GumElfMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  GumMipsWriter cw;
  gboolean has_tls = gum_elf_mapper_has_tls (self);
  const gsize frame_size = GUM_ELF_MIPS_FRAME_SIZE (1);
  const gsize ra_slot = GUM_ELF_MIPS_FRAME_SLOT (0);
  const GumElfTlsApi * api = &self->tls_api;
  guint i;

  gum_mips_writer_init (&cw, output_buffer);
  cw.pc = pc;

  if (has_tls)
    gum_emit_tls_get_addr (self, &cw);

  self->constructor_offset = gum_mips_writer_offset (&cw);
  gum_mips_writer_put_addi_reg_imm (&cw, MIPS_REG_SP, -frame_size);
  gum_mips_writer_put_sw_reg_reg_offset (&cw, MIPS_REG_RA, MIPS_REG_SP,
      ra_slot);
  gum_emit_indirect_bindings (self, &cw);
  if (has_tls)
  {
    gum_mips_writer_put_call_address_with_arguments (&cw, api->key_create, 2,
        GUM_ARG_ADDRESS, self->tls_key,
        GUM_ARG_ADDRESS, api->free);
  }
  for (i = 0; i != self->init_functions->len; i++)
  {
    GumAddress f = g_array_index (self->init_functions, GumAddress, i);

    gum_mips_writer_put_call_address_with_arguments (&cw, f, 3,
        GUM_ARG_ADDRESS, (GumAddress) 0,
        GUM_ARG_ADDRESS, (GumAddress) 0,
        GUM_ARG_ADDRESS, (GumAddress) 0);
  }
  gum_mips_writer_put_lw_reg_reg_offset (&cw, MIPS_REG_RA, MIPS_REG_SP,
      ra_slot);
  gum_mips_writer_put_addi_reg_imm (&cw, MIPS_REG_SP, frame_size);
  gum_mips_writer_put_ret (&cw);

  self->destructor_offset = gum_mips_writer_offset (&cw);
  gum_mips_writer_put_addi_reg_imm (&cw, MIPS_REG_SP, -frame_size);
  gum_mips_writer_put_sw_reg_reg_offset (&cw, MIPS_REG_RA, MIPS_REG_SP,
      ra_slot);
  for (i = 0; i != self->fini_functions->len; i++)
  {
    GumAddress f = g_array_index (self->fini_functions, GumAddress, i);

    gum_mips_writer_put_call_address_with_arguments (&cw, f, 0);
  }
  if (has_tls)
  {
    gum_emit_tls_key_load (self, &cw);
    gum_mips_writer_put_call_address_with_arguments (&cw, api->getspecific, 1,
        GUM_ARG_REGISTER, MIPS_REG_T0);
    gum_mips_writer_put_call_address_with_arguments (&cw, api->free, 1,
        GUM_ARG_REGISTER, MIPS_REG_V0);
    gum_emit_tls_key_load (self, &cw);
    gum_mips_writer_put_call_address_with_arguments (&cw, api->key_delete, 1,
        GUM_ARG_REGISTER, MIPS_REG_T0);
  }
  gum_mips_writer_put_lw_reg_reg_offset (&cw, MIPS_REG_RA, MIPS_REG_SP,
      ra_slot);
  gum_mips_writer_put_addi_reg_imm (&cw, MIPS_REG_SP, frame_size);
  gum_mips_writer_put_ret (&cw);

  gum_mips_writer_flush (&cw);
  *size = gum_mips_writer_offset (&cw);
  gum_mips_writer_clear (&cw);
}

static void
gum_emit_indirect_bindings (GumElfMapper * self,
                            GumMipsWriter * cw)
{
  guint i, j;

  for (i = 0; i != self->indirect_bindings->len; i++)
  {
    GumElfIndirectBinding * binding =
        g_ptr_array_index (self->indirect_bindings, i);

    gum_mips_writer_put_call_address_with_arguments (cw, binding->resolver, 0);

    for (j = 0; j != binding->slots->len; j++)
    {
      GumElfIndirectSlot * slot =
          &g_array_index (binding->slots, GumElfIndirectSlot, j);

      gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T1, slot->address);
      gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T2, slot->addend);
      gum_mips_writer_put_addu_reg_reg_reg (cw, MIPS_REG_T2, MIPS_REG_V0,
          MIPS_REG_T2);
      gum_mips_writer_put_sw_reg_reg_offset (cw, MIPS_REG_T2, MIPS_REG_T1, 0);
    }
  }
}

static void
gum_emit_tls_get_addr (GumElfMapper * self,
                       GumMipsWriter * cw)
{
  const gsize frame_size = GUM_ELF_MIPS_FRAME_SIZE (3);
  const mips_reg index_reg = MIPS_REG_S0;
  const gsize index_slot = GUM_ELF_MIPS_FRAME_SLOT (0);
  const mips_reg block_reg = MIPS_REG_S1;
  const gsize block_slot = GUM_ELF_MIPS_FRAME_SLOT (1);
  const gsize ra_slot = GUM_ELF_MIPS_FRAME_SLOT (2);
  const GumElfTlsApi * api = &self->tls_api;
  gconstpointer need_block = cw->code + 1;
  gconstpointer have_block = cw->code + 2;

  gum_mips_writer_put_addi_reg_imm (cw, MIPS_REG_SP, -frame_size);
  gum_mips_writer_put_sw_reg_reg_offset (cw, index_reg, MIPS_REG_SP,
      index_slot);
  gum_mips_writer_put_sw_reg_reg_offset (cw, block_reg, MIPS_REG_SP,
      block_slot);
  gum_mips_writer_put_sw_reg_reg_offset (cw, MIPS_REG_RA, MIPS_REG_SP,
      ra_slot);
  gum_mips_writer_put_move_reg_reg (cw, index_reg, MIPS_REG_A0);

  gum_emit_tls_key_load (self, cw);
  gum_mips_writer_put_call_address_with_arguments (cw, api->getspecific, 1,
      GUM_ARG_REGISTER, MIPS_REG_T0);
  gum_mips_writer_put_beq_reg_reg_label (cw, MIPS_REG_V0, MIPS_REG_ZERO,
      need_block);
  gum_mips_writer_put_beq_reg_reg_label (cw, MIPS_REG_ZERO, MIPS_REG_ZERO,
      have_block);

  gum_mips_writer_put_label (cw, need_block);
  gum_mips_writer_put_call_address_with_arguments (cw, api->calloc, 2,
      GUM_ARG_ADDRESS, (GumAddress) 1,
      GUM_ARG_ADDRESS, (GumAddress) self->tls.memory_size);
  gum_mips_writer_put_move_reg_reg (cw, block_reg, MIPS_REG_V0);
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T9, self->tls_memcpy);
  gum_mips_writer_put_lw_reg_reg_offset (cw, MIPS_REG_T9, MIPS_REG_T9, 0);
  gum_mips_writer_put_call_reg_with_arguments (cw, MIPS_REG_T9, 3,
      GUM_ARG_REGISTER, block_reg,
      GUM_ARG_ADDRESS, self->tls_template,
      GUM_ARG_ADDRESS, (GumAddress) self->tls.image_size);
  gum_emit_tls_key_load (self, cw);
  gum_mips_writer_put_call_address_with_arguments (cw, api->setspecific, 2,
      GUM_ARG_REGISTER, MIPS_REG_T0,
      GUM_ARG_REGISTER, block_reg);
  gum_mips_writer_put_move_reg_reg (cw, MIPS_REG_V0, block_reg);

  gum_mips_writer_put_label (cw, have_block);
  gum_mips_writer_put_lw_reg_reg_offset (cw, MIPS_REG_T1, index_reg,
      self->pointer_size);
  gum_mips_writer_put_addu_reg_reg_reg (cw, MIPS_REG_V0, MIPS_REG_V0,
      MIPS_REG_T1);
  gum_mips_writer_put_ori_reg_reg_imm (cw, MIPS_REG_T2, MIPS_REG_ZERO,
      GUM_ELF_MIPS_DTP_OFFSET);
  gum_mips_writer_put_addu_reg_reg_reg (cw, MIPS_REG_V0, MIPS_REG_V0,
      MIPS_REG_T2);

  gum_mips_writer_put_lw_reg_reg_offset (cw, index_reg, MIPS_REG_SP,
      index_slot);
  gum_mips_writer_put_lw_reg_reg_offset (cw, block_reg, MIPS_REG_SP,
      block_slot);
  gum_mips_writer_put_lw_reg_reg_offset (cw, MIPS_REG_RA, MIPS_REG_SP,
      ra_slot);
  gum_mips_writer_put_addi_reg_imm (cw, MIPS_REG_SP, frame_size);
  gum_mips_writer_put_ret (cw);
}

static void
gum_emit_tls_key_load (GumElfMapper * self,
                       GumMipsWriter * cw)
{
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T0, self->tls_key);
  gum_mips_writer_put_lw32_reg_reg_offset (cw, MIPS_REG_T0, MIPS_REG_T0, 0);
}

#else

static void
gum_emit_runtime (GumElfMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  g_assert_not_reached ();
}

#endif

static void
gum_elf_mapper_bind_tls_descriptors (GumElfMapper * self)
{
  guint i;

  for (i = 0; i != self->tls_desc_slots->len; i++)
  {
    GumAddress slot = g_array_index (self->tls_desc_slots, GumAddress, i);

    *((guint64 *) GUM_ELF_STAGED (self, slot)) = self->tls_desc_resolver;
  }
}

static gboolean
gum_commit_segment (const GumElfSegmentDetails * details,
                    gpointer user_data)
{
  GumElfMapper * self = user_data;
  GumProcessMemory * target = self->target;
  guint page_size = gum_query_page_size ();
  GumAddress start = details->vm_address + self->load_bias;
  GumAddress aligned_start = start & ~((GumAddress) page_size - 1);
  gsize aligned_size = GUM_ALIGN_SIZE (
      details->vm_size + (start - aligned_start), page_size);
  const guint8 * staged = GUM_ELF_STAGED (self, aligned_start);

  if (details->vm_size == 0)
    return TRUE;

  if ((details->protection & GUM_PAGE_WRITE) != 0)
  {
    gum_process_memory_write (target, aligned_start, staged,
        (start + details->file_size) - aligned_start);
    gum_process_memory_protect (target, aligned_start, aligned_size,
        details->protection);
  }
  else
  {
    gum_process_memory_map (target, aligned_start, aligned_size, staged,
        aligned_size, details->protection);
  }

  return TRUE;
}

static gboolean
gum_store_export (const GumExportDetails * details,
                  gpointer user_data)
{
  GumExportDetails * wanted = user_data;

  if (strcmp (details->name, wanted->name) != 0)
    return TRUE;

  wanted->address = details->address;

  return FALSE;
}

static gboolean
gum_elf_mapper_has_tls (GumElfMapper * self)
{
  return self->tls.memory_size != 0;
}

static GumCpuType
gum_cpu_type_from_elf (GumElfMachine machine)
{
  switch (machine)
  {
    case GUM_ELF_MACHINE_386:
      return GUM_CPU_IA32;
    case GUM_ELF_MACHINE_X86_64:
      return GUM_CPU_AMD64;
    case GUM_ELF_MACHINE_ARM:
      return GUM_CPU_ARM;
    case GUM_ELF_MACHINE_AARCH64:
      return GUM_CPU_ARM64;
    case GUM_ELF_MACHINE_MIPS:
      return GUM_CPU_MIPS;
    default:
      return GUM_CPU_INVALID;
  }
}
