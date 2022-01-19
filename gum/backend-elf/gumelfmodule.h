/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ELF_MODULE_H__
#define __GUM_ELF_MODULE_H__

#include <gum/gum.h>

G_BEGIN_DECLS

#define GUM_ELF_TYPE_MODULE (gum_elf_module_get_type ())
GUM_DECLARE_FINAL_TYPE (GumElfModule, gum_elf_module, GUM_ELF, MODULE, GObject)

typedef enum {
  GUM_ELF_MODE_OFFLINE,
  GUM_ELF_MODE_ONLINE,
} GumElfMode;

typedef enum {
  GUM_ELF_SYMBOL_NOTYPE = 0,
  GUM_ELF_SYMBOL_OBJECT = 1,
  GUM_ELF_SYMBOL_FUNC = 2,
  GUM_ELF_SYMBOL_SECTION = 3,
  GUM_ELF_SYMBOL_FILE = 4,
  GUM_ELF_SYMBOL_COMMON = 5,
  GUM_ELF_SYMBOL_TLS = 6,
  GUM_ELF_SYMBOL_NUM = 7,
  GUM_ELF_SYMBOL_LOOS = 10,
  GUM_ELF_SYMBOL_GNU_IFUNC = 10,
  GUM_ELF_SYMBOL_HIOS = 12,
  GUM_ELF_SYMBOL_LOPROC = 13,
  GUM_ELF_SYMBOL_SPARC_REGISTER = 13,
  GUM_ELF_SYMBOL_HIPROC = 15,
} GumElfSymbolType;

typedef enum {
  GUM_ELF_BIND_LOCAL = 0,
  GUM_ELF_BIND_GLOBAL = 1,
  GUM_ELF_BIND_WEAK = 2,
  GUM_ELF_BIND_LOOS = 10,
  GUM_ELF_BIND_GNU_UNIQUE = 10,
  GUM_ELF_BIND_HIOS = 12,
  GUM_ELF_BIND_LOPROC = 13,
  GUM_ELF_BIND_HIPROC = 15,
} GumElfSymbolBind;

typedef enum {
  GUM_ELF_DYNAMIC_NULL = 0,
  GUM_ELF_DYNAMIC_NEEDED = 1,
  GUM_ELF_DYNAMIC_PLTRELSZ = 2,
  GUM_ELF_DYNAMIC_PLTGOT = 3,
  GUM_ELF_DYNAMIC_HASH = 4,
  GUM_ELF_DYNAMIC_STRTAB = 5,
  GUM_ELF_DYNAMIC_SYMTAB = 6,
  GUM_ELF_DYNAMIC_RELA = 7,
  GUM_ELF_DYNAMIC_RELASZ = 8,
  GUM_ELF_DYNAMIC_RELAENT = 9,
  GUM_ELF_DYNAMIC_STRSZ = 10,
  GUM_ELF_DYNAMIC_SYMENT = 11,
  GUM_ELF_DYNAMIC_INIT = 12,
  GUM_ELF_DYNAMIC_FINI = 13,
  GUM_ELF_DYNAMIC_SONAME = 14,
  GUM_ELF_DYNAMIC_RPATH = 15,
  GUM_ELF_DYNAMIC_SYMBOLIC = 16,
  GUM_ELF_DYNAMIC_REL = 17,
  GUM_ELF_DYNAMIC_RELSZ = 18,
  GUM_ELF_DYNAMIC_RELENT = 19,
  GUM_ELF_DYNAMIC_PLTREL = 20,
  GUM_ELF_DYNAMIC_DEBUG = 21,
  GUM_ELF_DYNAMIC_TEXTREL = 22,
  GUM_ELF_DYNAMIC_JMPREL = 23,
  GUM_ELF_DYNAMIC_BIND_NOW = 24,
  GUM_ELF_DYNAMIC_INIT_ARRAY = 25,
  GUM_ELF_DYNAMIC_FINI_ARRAY = 26,
  GUM_ELF_DYNAMIC_INIT_ARRAYSZ = 27,
  GUM_ELF_DYNAMIC_FINI_ARRAYSZ = 28,
  GUM_ELF_DYNAMIC_RUNPATH = 29,
  GUM_ELF_DYNAMIC_FLAGS = 30,
  GUM_ELF_DYNAMIC_ENCODING = 32,
  GUM_ELF_DYNAMIC_PREINIT_ARRAY = 32,
  GUM_ELF_DYNAMIC_PREINIT_ARRAYSZ = 33,
  GUM_ELF_DYNAMIC_MAXPOSTAGS = 34,
  GUM_ELF_DYNAMIC_LOOS = 0x6000000d,
  GUM_ELF_DYNAMIC_SUNW_AUXILIARY = 0x6000000d,
  GUM_ELF_DYNAMIC_SUNW_RTLDINF = 0x6000000e,
  GUM_ELF_DYNAMIC_SUNW_FILTER = 0x6000000f,
  GUM_ELF_DYNAMIC_SUNW_CAP = 0x60000010,
  GUM_ELF_DYNAMIC_SUNW_ASLR = 0x60000023,
  GUM_ELF_DYNAMIC_HIOS = 0x6ffff000,

  GUM_ELF_DYNAMIC_VALRNGLO = 0x6ffffd00,
  GUM_ELF_DYNAMIC_GNU_PRELINKED = 0x6ffffdf5,
  GUM_ELF_DYNAMIC_GNU_CONFLICTSZ = 0x6ffffdf6,
  GUM_ELF_DYNAMIC_GNU_LIBLISTSZ = 0x6ffffdf7,
  GUM_ELF_DYNAMIC_CHECKSUM = 0x6ffffdf8,
  GUM_ELF_DYNAMIC_PLTPADSZ = 0x6ffffdf9,
  GUM_ELF_DYNAMIC_MOVEENT = 0x6ffffdfa,
  GUM_ELF_DYNAMIC_MOVESZ = 0x6ffffdfb,
  GUM_ELF_DYNAMIC_FEATURE = 0x6ffffdfc,
  GUM_ELF_DYNAMIC_FEATURE_1 = 0x6ffffdfc,
  GUM_ELF_DYNAMIC_POSFLAG_1 = 0x6ffffdfd,

  GUM_ELF_DYNAMIC_SYMINSZ = 0x6ffffdfe,
  GUM_ELF_DYNAMIC_SYMINENT = 0x6ffffdff,
  GUM_ELF_DYNAMIC_VALRNGHI = 0x6ffffdff,

  GUM_ELF_DYNAMIC_ADDRRNGLO = 0x6ffffe00,
  GUM_ELF_DYNAMIC_GNU_HASH = 0x6ffffef5,
  GUM_ELF_DYNAMIC_TLSDESC_PLT = 0x6ffffef6,
  GUM_ELF_DYNAMIC_TLSDESC_GOT = 0x6ffffef7,
  GUM_ELF_DYNAMIC_GNU_CONFLICT = 0x6ffffef8,
  GUM_ELF_DYNAMIC_GNU_LIBLIST = 0x6ffffef9,
  GUM_ELF_DYNAMIC_CONFIG = 0x6ffffefa,
  GUM_ELF_DYNAMIC_DEPAUDIT = 0x6ffffefb,
  GUM_ELF_DYNAMIC_AUDIT = 0x6ffffefc,
  GUM_ELF_DYNAMIC_PLTPAD = 0x6ffffefd,
  GUM_ELF_DYNAMIC_MOVETAB = 0x6ffffefe,
  GUM_ELF_DYNAMIC_SYMINFO = 0x6ffffeff,
  GUM_ELF_DYNAMIC_ADDRRNGHI = 0x6ffffeff,

  GUM_ELF_DYNAMIC_VERSYM = 0x6ffffff0,
  GUM_ELF_DYNAMIC_RELACOUNT = 0x6ffffff9,
  GUM_ELF_DYNAMIC_RELCOUNT = 0x6ffffffa,
  GUM_ELF_DYNAMIC_FLAGS_1 = 0x6ffffffb,
  GUM_ELF_DYNAMIC_VERDEF = 0x6ffffffc,
  GUM_ELF_DYNAMIC_VERDEFNUM = 0x6ffffffd,
  GUM_ELF_DYNAMIC_VERNEED = 0x6ffffffe,
  GUM_ELF_DYNAMIC_VERNEEDNUM = 0x6fffffff,

  GUM_ELF_DYNAMIC_LOPROC = 0x70000000,

  GUM_ELF_DYNAMIC_ARM_SYMTABSZ = 0x70000001,
  GUM_ELF_DYNAMIC_ARM_PREEMPTMAP = 0x70000002,

  GUM_ELF_DYNAMIC_SPARC_REGISTER = 0x70000001,
  GUM_ELF_DYNAMIC_DEPRECATED_SPARC_REGISTER = 0x7000001,

  GUM_ELF_DYNAMIC_MIPS_RLD_VERSION = 0x70000001,
  GUM_ELF_DYNAMIC_MIPS_TIME_STAMP = 0x70000002,
  GUM_ELF_DYNAMIC_MIPS_ICHECKSUM = 0x70000003,
  GUM_ELF_DYNAMIC_MIPS_IVERSION = 0x70000004,
  GUM_ELF_DYNAMIC_MIPS_FLAGS = 0x70000005,
  GUM_ELF_DYNAMIC_MIPS_BASE_ADDRESS = 0x70000006,
  GUM_ELF_DYNAMIC_MIPS_CONFLICT = 0x70000008,
  GUM_ELF_DYNAMIC_MIPS_LIBLIST = 0x70000009,
  GUM_ELF_DYNAMIC_MIPS_LOCAL_GOTNO = 0x7000000a,
  GUM_ELF_DYNAMIC_MIPS_CONFLICTNO = 0x7000000b,
  GUM_ELF_DYNAMIC_MIPS_LIBLISTNO = 0x70000010,
  GUM_ELF_DYNAMIC_MIPS_SYMTABNO = 0x70000011,
  GUM_ELF_DYNAMIC_MIPS_UNREFEXTNO = 0x70000012,
  GUM_ELF_DYNAMIC_MIPS_GOTSYM = 0x70000013,
  GUM_ELF_DYNAMIC_MIPS_HIPAGENO = 0x70000014,
  GUM_ELF_DYNAMIC_MIPS_RLD_MAP = 0x70000016,
  GUM_ELF_DYNAMIC_MIPS_DELTA_CLASS = 0x70000017,
  GUM_ELF_DYNAMIC_MIPS_DELTA_CLASS_NO = 0x70000018,
  GUM_ELF_DYNAMIC_MIPS_DELTA_INSTANCE = 0x70000019,
  GUM_ELF_DYNAMIC_MIPS_DELTA_INSTANCE_NO = 0x7000001a,
  GUM_ELF_DYNAMIC_MIPS_DELTA_RELOC = 0x7000001b,
  GUM_ELF_DYNAMIC_MIPS_DELTA_RELOC_NO = 0x7000001c,
  GUM_ELF_DYNAMIC_MIPS_DELTA_SYM = 0x7000001d,
  GUM_ELF_DYNAMIC_MIPS_DELTA_SYM_NO = 0x7000001e,
  GUM_ELF_DYNAMIC_MIPS_DELTA_CLASSSYM = 0x70000020,
  GUM_ELF_DYNAMIC_MIPS_DELTA_CLASSSYM_NO = 0x70000021,
  GUM_ELF_DYNAMIC_MIPS_CXX_FLAGS = 0x70000022,
  GUM_ELF_DYNAMIC_MIPS_PIXIE_INIT = 0x70000023,
  GUM_ELF_DYNAMIC_MIPS_SYMBOL_LIB = 0x70000024,
  GUM_ELF_DYNAMIC_MIPS_LOCALPAGE_GOTIDX = 0x70000025,
  GUM_ELF_DYNAMIC_MIPS_LOCAL_GOTIDX = 0x70000026,
  GUM_ELF_DYNAMIC_MIPS_HIDDEN_GOTIDX = 0x70000027,
  GUM_ELF_DYNAMIC_MIPS_PROTECTED_GOTIDX = 0x70000028,
  GUM_ELF_DYNAMIC_MIPS_OPTIONS = 0x70000029,
  GUM_ELF_DYNAMIC_MIPS_INTERFACE = 0x7000002a,
  GUM_ELF_DYNAMIC_MIPS_DYNSTR_ALIGN = 0x7000002b,
  GUM_ELF_DYNAMIC_MIPS_INTERFACE_SIZE = 0x7000002c,
  GUM_ELF_DYNAMIC_MIPS_RLD_TEXT_RESOLVE_ADDR = 0x7000002d,
  GUM_ELF_DYNAMIC_MIPS_PERF_SUFFIX = 0x7000002e,
  GUM_ELF_DYNAMIC_MIPS_COMPACT_SIZE = 0x7000002f,
  GUM_ELF_DYNAMIC_MIPS_GP_VALUE = 0x70000030,
  GUM_ELF_DYNAMIC_MIPS_AUX_DYNAMIC = 0x70000031,
  GUM_ELF_DYNAMIC_MIPS_PLTGOT = 0x70000032,
  GUM_ELF_DYNAMIC_MIPS_RLD_OBJ_UPDATE = 0x70000033,
  GUM_ELF_DYNAMIC_MIPS_RWPLT = 0x70000034,
  GUM_ELF_DYNAMIC_MIPS_RLD_MAP_REL = 0x70000035,

  GUM_ELF_DYNAMIC_PPC_GOT = 0x70000000,
  GUM_ELF_DYNAMIC_PPC_TLSOPT = 0x70000001,

  GUM_ELF_DYNAMIC_PPC64_GLINK = 0x70000000,
  GUM_ELF_DYNAMIC_PPC64_OPD = 0x70000001,
  GUM_ELF_DYNAMIC_PPC64_OPDSZ = 0x70000002,
  GUM_ELF_DYNAMIC_PPC64_TLSOPT = 0x70000003,

  GUM_ELF_DYNAMIC_AUXILIARY = 0x7ffffffd,
  GUM_ELF_DYNAMIC_USED = 0x7ffffffe,
  GUM_ELF_DYNAMIC_FILTER = 0x7fffffff,
  GUM_ELF_DYNAMIC_HIPROC = 0x7fffffff,
} GumElfDynamicTag;

typedef struct _GumElfDependencyDetails GumElfDependencyDetails;
typedef struct _GumElfSymbolDetails GumElfSymbolDetails;
typedef struct _GumElfDynamicEntryDetails GumElfDynamicEntryDetails;
typedef struct _GumElfSectionDetails GumElfSectionDetails;

typedef gboolean (* GumFoundElfDependencyFunc) (
    const GumElfDependencyDetails * details, gpointer user_data);
typedef gboolean (* GumFoundElfSymbolFunc) (const GumElfSymbolDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundElfDynamicEntryFunc) (
    const GumElfDynamicEntryDetails * details, gpointer user_data);
typedef gboolean (* GumFoundElfSectionFunc) (
    const GumElfSectionDetails * details, gpointer user_data);

struct _GumElfDependencyDetails
{
  const gchar * name;
};

struct _GumElfSymbolDetails
{
  const gchar * name;
  GumAddress address;
  gsize size;
  GumElfSymbolType type;
  GumElfSymbolBind bind;
  guint16 section_header_index;
};

struct _GumElfDynamicEntryDetails
{
  GumElfDynamicTag tag;
  guint64 val;
};

struct _GumElfSectionDetails
{
  const gchar * name;
  guint32 type;
  guint64 flags;
  GumAddress address;
  guint64 offset;
  gsize size;
  guint32 link;
  guint32 info;
  guint64 alignment;
  guint64 entry_size;
  GumPageProtection protection;
};

GUM_API GumElfModule * gum_elf_module_new_from_file (const gchar * path,
    GError ** error);
GUM_API GumElfModule * gum_elf_module_new_from_memory (const gchar * path,
    GumAddress base_address, GError ** error);

GUM_API gboolean gum_elf_module_load (GumElfModule * self, GError ** error);

GUM_API const gchar * gum_elf_module_get_name (GumElfModule * self);
GUM_API const gchar * gum_elf_module_get_path (GumElfModule * self);
GUM_API GumAddress gum_elf_module_get_base_address (GumElfModule * self);
GUM_API GumAddress gum_elf_module_get_preferred_address (GumElfModule * self);
GUM_API GumAddress gum_elf_module_get_entrypoint (GumElfModule * self);
GUM_API gpointer gum_elf_module_get_elf (GumElfModule * self);
GUM_API gconstpointer gum_elf_module_get_file_data (GumElfModule * self);
GUM_API gboolean gum_elf_module_has_interp (GumElfModule * self);

GUM_API void gum_elf_module_enumerate_dependencies (GumElfModule * self,
    GumFoundElfDependencyFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_imports (GumElfModule * self,
    GumFoundImportFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_exports (GumElfModule * self,
    GumFoundExportFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_dynamic_symbols (GumElfModule * self,
    GumFoundElfSymbolFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_symbols (GumElfModule * self,
    GumFoundElfSymbolFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_dynamic_entries (GumElfModule * self,
    GumFoundElfDynamicEntryFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_sections (GumElfModule * self,
    GumFoundElfSectionFunc func, gpointer user_data);

GUM_API GumAddress gum_elf_module_translate_to_offline (GumElfModule * self,
    GumAddress online_address);
GUM_API GumAddress gum_elf_module_translate_to_online (GumElfModule * self,
    GumAddress offline_address);

G_END_DECLS

#endif
