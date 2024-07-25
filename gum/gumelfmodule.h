/*
 * Copyright (C) 2010-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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
  GUM_ELF_NONE,
  GUM_ELF_REL,
  GUM_ELF_EXEC,
  GUM_ELF_DYN,
  GUM_ELF_CORE,
} GumElfType;

typedef enum {
  GUM_ELF_OS_SYSV,
  GUM_ELF_OS_HPUX,
  GUM_ELF_OS_NETBSD,
  GUM_ELF_OS_LINUX,
  GUM_ELF_OS_SOLARIS = 6,
  GUM_ELF_OS_AIX,
  GUM_ELF_OS_IRIX,
  GUM_ELF_OS_FREEBSD,
  GUM_ELF_OS_TRU64,
  GUM_ELF_OS_MODESTO,
  GUM_ELF_OS_OPENBSD,
  GUM_ELF_OS_ARM_AEABI = 64,
  GUM_ELF_OS_ARM = 97,
  GUM_ELF_OS_STANDALONE = 255,
} GumElfOSABI;

typedef enum {
  GUM_ELF_MACHINE_NONE,
  GUM_ELF_MACHINE_M32,
  GUM_ELF_MACHINE_SPARC,
  GUM_ELF_MACHINE_386,
  GUM_ELF_MACHINE_68K,
  GUM_ELF_MACHINE_88K,
  GUM_ELF_MACHINE_IAMCU,
  GUM_ELF_MACHINE_860,
  GUM_ELF_MACHINE_MIPS,
  GUM_ELF_MACHINE_S370,
  GUM_ELF_MACHINE_MIPS_RS3_LE,

  GUM_ELF_MACHINE_PARISC = 15,

  GUM_ELF_MACHINE_VPP500 = 17,
  GUM_ELF_MACHINE_SPARC32PLUS,
  GUM_ELF_MACHINE_960,
  GUM_ELF_MACHINE_PPC,
  GUM_ELF_MACHINE_PPC64,
  GUM_ELF_MACHINE_S390,
  GUM_ELF_MACHINE_SPU,

  GUM_ELF_MACHINE_V800 = 36,
  GUM_ELF_MACHINE_FR20,
  GUM_ELF_MACHINE_RH32,
  GUM_ELF_MACHINE_RCE,
  GUM_ELF_MACHINE_ARM,
  GUM_ELF_MACHINE_FAKE_ALPHA,
  GUM_ELF_MACHINE_SH,
  GUM_ELF_MACHINE_SPARCV9,
  GUM_ELF_MACHINE_TRICORE,
  GUM_ELF_MACHINE_ARC,
  GUM_ELF_MACHINE_H8_300,
  GUM_ELF_MACHINE_H8_300H,
  GUM_ELF_MACHINE_H8S,
  GUM_ELF_MACHINE_H8_500,
  GUM_ELF_MACHINE_IA_64,
  GUM_ELF_MACHINE_MIPS_X,
  GUM_ELF_MACHINE_COLDFIRE,
  GUM_ELF_MACHINE_68HC12,
  GUM_ELF_MACHINE_MMA,
  GUM_ELF_MACHINE_PCP,
  GUM_ELF_MACHINE_NCPU,
  GUM_ELF_MACHINE_NDR1,
  GUM_ELF_MACHINE_STARCORE,
  GUM_ELF_MACHINE_ME16,
  GUM_ELF_MACHINE_ST100,
  GUM_ELF_MACHINE_TINYJ,
  GUM_ELF_MACHINE_X86_64,
  GUM_ELF_MACHINE_PDSP,
  GUM_ELF_MACHINE_PDP10,
  GUM_ELF_MACHINE_PDP11,
  GUM_ELF_MACHINE_FX66,
  GUM_ELF_MACHINE_ST9PLUS,
  GUM_ELF_MACHINE_ST7,
  GUM_ELF_MACHINE_68HC16,
  GUM_ELF_MACHINE_68HC11,
  GUM_ELF_MACHINE_68HC08,
  GUM_ELF_MACHINE_68HC05,
  GUM_ELF_MACHINE_SVX,
  GUM_ELF_MACHINE_ST19,
  GUM_ELF_MACHINE_VAX,
  GUM_ELF_MACHINE_CRIS,
  GUM_ELF_MACHINE_JAVELIN,
  GUM_ELF_MACHINE_FIREPATH,
  GUM_ELF_MACHINE_ZSP,
  GUM_ELF_MACHINE_MMIX,
  GUM_ELF_MACHINE_HUANY,
  GUM_ELF_MACHINE_PRISM,
  GUM_ELF_MACHINE_AVR,
  GUM_ELF_MACHINE_FR30,
  GUM_ELF_MACHINE_D10V,
  GUM_ELF_MACHINE_D30V,
  GUM_ELF_MACHINE_V850,
  GUM_ELF_MACHINE_M32R,
  GUM_ELF_MACHINE_MN10300,
  GUM_ELF_MACHINE_MN10200,
  GUM_ELF_MACHINE_PJ,
  GUM_ELF_MACHINE_OPENRISC,
  GUM_ELF_MACHINE_ARC_COMPACT,
  GUM_ELF_MACHINE_XTENSA,
  GUM_ELF_MACHINE_VIDEOCORE,
  GUM_ELF_MACHINE_TMM_GPP,
  GUM_ELF_MACHINE_NS32K,
  GUM_ELF_MACHINE_TPC,
  GUM_ELF_MACHINE_SNP1K,
  GUM_ELF_MACHINE_ST200,
  GUM_ELF_MACHINE_IP2K,
  GUM_ELF_MACHINE_MAX,
  GUM_ELF_MACHINE_CR,
  GUM_ELF_MACHINE_F2MC16,
  GUM_ELF_MACHINE_MSP430,
  GUM_ELF_MACHINE_BLACKFIN,
  GUM_ELF_MACHINE_SE_C33,
  GUM_ELF_MACHINE_SEP,
  GUM_ELF_MACHINE_ARCA,
  GUM_ELF_MACHINE_UNICORE,
  GUM_ELF_MACHINE_EXCESS,
  GUM_ELF_MACHINE_DXP,
  GUM_ELF_MACHINE_ALTERA_NIOS2,
  GUM_ELF_MACHINE_CRX,
  GUM_ELF_MACHINE_XGATE,
  GUM_ELF_MACHINE_C166,
  GUM_ELF_MACHINE_M16C,
  GUM_ELF_MACHINE_DSPIC30F,
  GUM_ELF_MACHINE_CE,
  GUM_ELF_MACHINE_M32C,

  GUM_ELF_MACHINE_TSK3000 = 131,
  GUM_ELF_MACHINE_RS08,
  GUM_ELF_MACHINE_SHARC,
  GUM_ELF_MACHINE_ECOG2,
  GUM_ELF_MACHINE_SCORE7,
  GUM_ELF_MACHINE_DSP24,
  GUM_ELF_MACHINE_VIDEOCORE3,
  GUM_ELF_MACHINE_LATTICEMICO32,
  GUM_ELF_MACHINE_SE_C17,
  GUM_ELF_MACHINE_TI_C6000,
  GUM_ELF_MACHINE_TI_C2000,
  GUM_ELF_MACHINE_TI_C5500,
  GUM_ELF_MACHINE_TI_ARP32,
  GUM_ELF_MACHINE_TI_PRU,

  GUM_ELF_MACHINE_MMDSP_PLUS = 160,
  GUM_ELF_MACHINE_CYPRESS_M8C,
  GUM_ELF_MACHINE_R32C,
  GUM_ELF_MACHINE_TRIMEDIA,
  GUM_ELF_MACHINE_QDSP6,
  GUM_ELF_MACHINE_8051,
  GUM_ELF_MACHINE_STXP7X,
  GUM_ELF_MACHINE_NDS32,
  GUM_ELF_MACHINE_ECOG1X,
  GUM_ELF_MACHINE_MAXQ30,
  GUM_ELF_MACHINE_XIMO16,
  GUM_ELF_MACHINE_MANIK,
  GUM_ELF_MACHINE_CRAYNV2,
  GUM_ELF_MACHINE_RX,
  GUM_ELF_MACHINE_METAG,
  GUM_ELF_MACHINE_MCST_ELBRUS,
  GUM_ELF_MACHINE_ECOG16,
  GUM_ELF_MACHINE_CR16,
  GUM_ELF_MACHINE_ETPU,
  GUM_ELF_MACHINE_SLE9X,
  GUM_ELF_MACHINE_L10M,
  GUM_ELF_MACHINE_K10M,

  GUM_ELF_MACHINE_AARCH64 = 183,

  GUM_ELF_MACHINE_AVR32 = 185,
  GUM_ELF_MACHINE_STM8,
  GUM_ELF_MACHINE_TILE64,
  GUM_ELF_MACHINE_TILEPRO,
  GUM_ELF_MACHINE_MICROBLAZE,
  GUM_ELF_MACHINE_CUDA,
  GUM_ELF_MACHINE_TILEGX,
  GUM_ELF_MACHINE_CLOUDSHIELD,
  GUM_ELF_MACHINE_COREA_1ST,
  GUM_ELF_MACHINE_COREA_2ND,
  GUM_ELF_MACHINE_ARCV2,
  GUM_ELF_MACHINE_OPEN8,
  GUM_ELF_MACHINE_RL78,
  GUM_ELF_MACHINE_VIDEOCORE5,
  GUM_ELF_MACHINE_78KOR,
  GUM_ELF_MACHINE_56800EX,
  GUM_ELF_MACHINE_BA1,
  GUM_ELF_MACHINE_BA2,
  GUM_ELF_MACHINE_XCORE,
  GUM_ELF_MACHINE_MCHP_PIC,

  GUM_ELF_MACHINE_KM32 = 210,
  GUM_ELF_MACHINE_KMX32,
  GUM_ELF_MACHINE_EMX16,
  GUM_ELF_MACHINE_EMX8,
  GUM_ELF_MACHINE_KVARC,
  GUM_ELF_MACHINE_CDP,
  GUM_ELF_MACHINE_COGE,
  GUM_ELF_MACHINE_COOL,
  GUM_ELF_MACHINE_NORC,
  GUM_ELF_MACHINE_CSR_KALIMBA,
  GUM_ELF_MACHINE_Z80,
  GUM_ELF_MACHINE_VISIUM,
  GUM_ELF_MACHINE_FT32,
  GUM_ELF_MACHINE_MOXIE,
  GUM_ELF_MACHINE_AMDGPU,

  GUM_ELF_MACHINE_RISCV = 243,

  GUM_ELF_MACHINE_BPF = 247,

  GUM_ELF_MACHINE_CSKY = 252,

  GUM_ELF_MACHINE_ALPHA = 0x9026,
} GumElfMachine;

typedef enum {
  GUM_ELF_SOURCE_MODE_OFFLINE,
  GUM_ELF_SOURCE_MODE_ONLINE,
} GumElfSourceMode;

typedef enum {
  GUM_ELF_SECTION_NULL,
  GUM_ELF_SECTION_PROGBITS,
  GUM_ELF_SECTION_SYMTAB,
  GUM_ELF_SECTION_STRTAB,
  GUM_ELF_SECTION_RELA,
  GUM_ELF_SECTION_HASH,
  GUM_ELF_SECTION_DYNAMIC,
  GUM_ELF_SECTION_NOTE,
  GUM_ELF_SECTION_NOBITS,
  GUM_ELF_SECTION_REL,
  GUM_ELF_SECTION_SHLIB,
  GUM_ELF_SECTION_DYNSYM,
  GUM_ELF_SECTION_INIT_ARRAY = 14,
  GUM_ELF_SECTION_FINI_ARRAY,
  GUM_ELF_SECTION_PREINIT_ARRAY,
  GUM_ELF_SECTION_GROUP,
  GUM_ELF_SECTION_SYMTAB_SHNDX,
  GUM_ELF_SECTION_RELR,
  GUM_ELF_SECTION_NUM,
  GUM_ELF_SECTION_GNU_ATTRIBUTES = 0x6ffffff5,
  GUM_ELF_SECTION_GNU_HASH       = 0x6ffffff6,
  GUM_ELF_SECTION_GNU_LIBLIST    = 0x6ffffff7,
  GUM_ELF_SECTION_CHECKSUM       = 0x6ffffff8,
  GUM_ELF_SECTION_SUNW_MOVE      = 0x6ffffffa,
  GUM_ELF_SECTION_SUNW_COMDAT    = 0x6ffffffb,
  GUM_ELF_SECTION_SUNW_SYMINFO   = 0x6ffffffc,
  GUM_ELF_SECTION_GNU_VERDEF     = 0x6ffffffd,
  GUM_ELF_SECTION_GNU_VERNEED    = 0x6ffffffe,
  GUM_ELF_SECTION_GNU_VERSYM     = 0x6fffffff,
} GumElfSectionType;

typedef enum {
  GUM_ELF_DYNAMIC_NULL,
  GUM_ELF_DYNAMIC_NEEDED,
  GUM_ELF_DYNAMIC_PLTRELSZ,
  GUM_ELF_DYNAMIC_PLTGOT,
  GUM_ELF_DYNAMIC_HASH,
  GUM_ELF_DYNAMIC_STRTAB,
  GUM_ELF_DYNAMIC_SYMTAB,
  GUM_ELF_DYNAMIC_RELA,
  GUM_ELF_DYNAMIC_RELASZ,
  GUM_ELF_DYNAMIC_RELAENT,
  GUM_ELF_DYNAMIC_STRSZ,
  GUM_ELF_DYNAMIC_SYMENT,
  GUM_ELF_DYNAMIC_INIT,
  GUM_ELF_DYNAMIC_FINI,
  GUM_ELF_DYNAMIC_SONAME,
  GUM_ELF_DYNAMIC_RPATH,
  GUM_ELF_DYNAMIC_SYMBOLIC,
  GUM_ELF_DYNAMIC_REL,
  GUM_ELF_DYNAMIC_RELSZ,
  GUM_ELF_DYNAMIC_RELENT,
  GUM_ELF_DYNAMIC_PLTREL,
  GUM_ELF_DYNAMIC_DEBUG,
  GUM_ELF_DYNAMIC_TEXTREL,
  GUM_ELF_DYNAMIC_JMPREL,
  GUM_ELF_DYNAMIC_BIND_NOW,
  GUM_ELF_DYNAMIC_INIT_ARRAY,
  GUM_ELF_DYNAMIC_FINI_ARRAY,
  GUM_ELF_DYNAMIC_INIT_ARRAYSZ,
  GUM_ELF_DYNAMIC_FINI_ARRAYSZ,
  GUM_ELF_DYNAMIC_RUNPATH,
  GUM_ELF_DYNAMIC_FLAGS,
  GUM_ELF_DYNAMIC_ENCODING = 32,
  GUM_ELF_DYNAMIC_PREINIT_ARRAY = 32,
  GUM_ELF_DYNAMIC_PREINIT_ARRAYSZ,
  GUM_ELF_DYNAMIC_MAXPOSTAGS,

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

typedef enum {
  GUM_ELF_SHDR_INDEX_UNDEF,
  GUM_ELF_SHDR_INDEX_BEFORE    = 0xff00,
  GUM_ELF_SHDR_INDEX_AFTER     = 0xff01,
  GUM_ELF_SHDR_INDEX_ABS       = 0xfff1,
  GUM_ELF_SHDR_INDEX_COMMON    = 0xfff2,
  GUM_ELF_SHDR_INDEX_XINDEX    = 0xffff,
} GumElfShdrIndex;

typedef enum {
  GUM_ELF_SYMBOL_NOTYPE,
  GUM_ELF_SYMBOL_OBJECT,
  GUM_ELF_SYMBOL_FUNC,
  GUM_ELF_SYMBOL_SECTION,
  GUM_ELF_SYMBOL_FILE,
  GUM_ELF_SYMBOL_COMMON,
  GUM_ELF_SYMBOL_TLS,
  GUM_ELF_SYMBOL_NUM,
  GUM_ELF_SYMBOL_LOOS = 10,
  GUM_ELF_SYMBOL_GNU_IFUNC = 10,
  GUM_ELF_SYMBOL_HIOS = 12,
  GUM_ELF_SYMBOL_LOPROC,
  GUM_ELF_SYMBOL_SPARC_REGISTER = 13,
  GUM_ELF_SYMBOL_HIPROC = 15,
} GumElfSymbolType;

typedef enum {
  GUM_ELF_BIND_LOCAL,
  GUM_ELF_BIND_GLOBAL,
  GUM_ELF_BIND_WEAK,

  GUM_ELF_BIND_LOOS = 10,
  GUM_ELF_BIND_GNU_UNIQUE = 10,
  GUM_ELF_BIND_HIOS = 12,

  GUM_ELF_BIND_LOPROC,
  GUM_ELF_BIND_HIPROC = 15,
} GumElfSymbolBind;

typedef enum {
  GUM_ELF_IA32_NONE,
  GUM_ELF_IA32_32,
  GUM_ELF_IA32_PC32,
  GUM_ELF_IA32_GOT32,
  GUM_ELF_IA32_PLT32,
  GUM_ELF_IA32_COPY,
  GUM_ELF_IA32_GLOB_DAT,
  GUM_ELF_IA32_JMP_SLOT,
  GUM_ELF_IA32_RELATIVE,
  GUM_ELF_IA32_GOTOFF,
  GUM_ELF_IA32_GOTPC,
  GUM_ELF_IA32_32PLT,
  GUM_ELF_IA32_TLS_TPOFF = 14,
  GUM_ELF_IA32_TLS_IE,
  GUM_ELF_IA32_TLS_GOTIE,
  GUM_ELF_IA32_TLS_LE,
  GUM_ELF_IA32_TLS_GD,
  GUM_ELF_IA32_TLS_LDM,
  GUM_ELF_IA32_16,
  GUM_ELF_IA32_PC16,
  GUM_ELF_IA32_8,
  GUM_ELF_IA32_PC8,
  GUM_ELF_IA32_TLS_GD_32,
  GUM_ELF_IA32_TLS_GD_PUSH,
  GUM_ELF_IA32_TLS_GD_CALL,
  GUM_ELF_IA32_TLS_GD_POP,
  GUM_ELF_IA32_TLS_LDM_32,
  GUM_ELF_IA32_TLS_LDM_PUSH,
  GUM_ELF_IA32_TLS_LDM_CALL,
  GUM_ELF_IA32_TLS_LDM_POP,
  GUM_ELF_IA32_TLS_LDO_32,
  GUM_ELF_IA32_TLS_IE_32,
  GUM_ELF_IA32_TLS_LE_32,
  GUM_ELF_IA32_TLS_DTPMOD32,
  GUM_ELF_IA32_TLS_DTPOFF32,
  GUM_ELF_IA32_TLS_TPOFF32,
  GUM_ELF_IA32_SIZE32,
  GUM_ELF_IA32_TLS_GOTDESC,
  GUM_ELF_IA32_TLS_DESC_CALL,
  GUM_ELF_IA32_TLS_DESC,
  GUM_ELF_IA32_IRELATIVE,
  GUM_ELF_IA32_GOT32X,
} GumElfIA32Relocation;

typedef enum {
  GUM_ELF_X64_NONE,
  GUM_ELF_X64_64,
  GUM_ELF_X64_PC32,
  GUM_ELF_X64_GOT32,
  GUM_ELF_X64_PLT32,
  GUM_ELF_X64_COPY,
  GUM_ELF_X64_GLOB_DAT,
  GUM_ELF_X64_JUMP_SLOT,
  GUM_ELF_X64_RELATIVE,
  GUM_ELF_X64_GOTPCREL,
  GUM_ELF_X64_32,
  GUM_ELF_X64_32S,
  GUM_ELF_X64_16,
  GUM_ELF_X64_PC16,
  GUM_ELF_X64_8,
  GUM_ELF_X64_PC8,
  GUM_ELF_X64_DTPMOD64,
  GUM_ELF_X64_DTPOFF64,
  GUM_ELF_X64_TPOFF64,
  GUM_ELF_X64_TLSGD,
  GUM_ELF_X64_TLSLD,
  GUM_ELF_X64_DTPOFF32,
  GUM_ELF_X64_GOTTPOFF,
  GUM_ELF_X64_TPOFF32,
  GUM_ELF_X64_PC64,
  GUM_ELF_X64_GOTOFF64,
  GUM_ELF_X64_GOTPC32,
  GUM_ELF_X64_GOT64,
  GUM_ELF_X64_GOTPCREL64,
  GUM_ELF_X64_GOTPC64,
  GUM_ELF_X64_GOTPLT64,
  GUM_ELF_X64_PLTOFF64,
  GUM_ELF_X64_SIZE32,
  GUM_ELF_X64_SIZE64,
  GUM_ELF_X64_GOTPC32_TLSDESC,
  GUM_ELF_X64_TLSDESC_CALL,
  GUM_ELF_X64_TLSDESC,
  GUM_ELF_X64_IRELATIVE,
  GUM_ELF_X64_RELATIVE64,
  GUM_ELF_X64_GOTPCRELX = 41,
  GUM_ELF_X64_REX_GOTPCRELX,
} GumElfX64Relocation;

typedef enum {
  GUM_ELF_ARM_NONE,
  GUM_ELF_ARM_PC24,
  GUM_ELF_ARM_ABS32,
  GUM_ELF_ARM_REL32,
  GUM_ELF_ARM_PC13,
  GUM_ELF_ARM_ABS16,
  GUM_ELF_ARM_ABS12,
  GUM_ELF_ARM_THM_ABS5,
  GUM_ELF_ARM_ABS8,
  GUM_ELF_ARM_SBREL32,
  GUM_ELF_ARM_THM_PC22,
  GUM_ELF_ARM_THM_PC8,
  GUM_ELF_ARM_AMP_VCALL9,
  GUM_ELF_ARM_SWI24,
  GUM_ELF_ARM_TLS_DESC = 13,
  GUM_ELF_ARM_THM_SWI8,
  GUM_ELF_ARM_XPC25,
  GUM_ELF_ARM_THM_XPC22,
  GUM_ELF_ARM_TLS_DTPMOD32,
  GUM_ELF_ARM_TLS_DTPOFF32,
  GUM_ELF_ARM_TLS_TPOFF32,
  GUM_ELF_ARM_COPY,
  GUM_ELF_ARM_GLOB_DAT,
  GUM_ELF_ARM_JUMP_SLOT,
  GUM_ELF_ARM_RELATIVE,
  GUM_ELF_ARM_GOTOFF,
  GUM_ELF_ARM_GOTPC,
  GUM_ELF_ARM_GOT32,
  GUM_ELF_ARM_PLT32,
  GUM_ELF_ARM_CALL,
  GUM_ELF_ARM_JUMP24,
  GUM_ELF_ARM_THM_JUMP24,
  GUM_ELF_ARM_BASE_ABS,
  GUM_ELF_ARM_ALU_PCREL_7_0,
  GUM_ELF_ARM_ALU_PCREL_15_8,
  GUM_ELF_ARM_ALU_PCREL_23_15,
  GUM_ELF_ARM_LDR_SBREL_11_0,
  GUM_ELF_ARM_ALU_SBREL_19_12,
  GUM_ELF_ARM_ALU_SBREL_27_20,
  GUM_ELF_ARM_TARGET1,
  GUM_ELF_ARM_SBREL31,
  GUM_ELF_ARM_V4BX,
  GUM_ELF_ARM_TARGET2,
  GUM_ELF_ARM_PREL31,
  GUM_ELF_ARM_MOVW_ABS_NC,
  GUM_ELF_ARM_MOVT_ABS,
  GUM_ELF_ARM_MOVW_PREL_NC,
  GUM_ELF_ARM_MOVT_PREL,
  GUM_ELF_ARM_THM_MOVW_ABS_NC,
  GUM_ELF_ARM_THM_MOVT_ABS,
  GUM_ELF_ARM_THM_MOVW_PREL_NC,
  GUM_ELF_ARM_THM_MOVT_PREL,
  GUM_ELF_ARM_THM_JUMP19,
  GUM_ELF_ARM_THM_JUMP6,
  GUM_ELF_ARM_THM_ALU_PREL_11_0,
  GUM_ELF_ARM_THM_PC12,
  GUM_ELF_ARM_ABS32_NOI,
  GUM_ELF_ARM_REL32_NOI,
  GUM_ELF_ARM_ALU_PC_G0_NC,
  GUM_ELF_ARM_ALU_PC_G0,
  GUM_ELF_ARM_ALU_PC_G1_NC,
  GUM_ELF_ARM_ALU_PC_G1,
  GUM_ELF_ARM_ALU_PC_G2,
  GUM_ELF_ARM_LDR_PC_G1,
  GUM_ELF_ARM_LDR_PC_G2,
  GUM_ELF_ARM_LDRS_PC_G0,
  GUM_ELF_ARM_LDRS_PC_G1,
  GUM_ELF_ARM_LDRS_PC_G2,
  GUM_ELF_ARM_LDC_PC_G0,
  GUM_ELF_ARM_LDC_PC_G1,
  GUM_ELF_ARM_LDC_PC_G2,
  GUM_ELF_ARM_ALU_SB_G0_NC,
  GUM_ELF_ARM_ALU_SB_G0,
  GUM_ELF_ARM_ALU_SB_G1_NC,
  GUM_ELF_ARM_ALU_SB_G1,
  GUM_ELF_ARM_ALU_SB_G2,
  GUM_ELF_ARM_LDR_SB_G0,
  GUM_ELF_ARM_LDR_SB_G1,
  GUM_ELF_ARM_LDR_SB_G2,
  GUM_ELF_ARM_LDRS_SB_G0,
  GUM_ELF_ARM_LDRS_SB_G1,
  GUM_ELF_ARM_LDRS_SB_G2,
  GUM_ELF_ARM_LDC_SB_G0,
  GUM_ELF_ARM_LDC_SB_G1,
  GUM_ELF_ARM_LDC_SB_G2,
  GUM_ELF_ARM_MOVW_BREL_NC,
  GUM_ELF_ARM_MOVT_BREL,
  GUM_ELF_ARM_MOVW_BREL,
  GUM_ELF_ARM_THM_MOVW_BREL_NC,
  GUM_ELF_ARM_THM_MOVT_BREL,
  GUM_ELF_ARM_THM_MOVW_BREL,
  GUM_ELF_ARM_TLS_GOTDESC,
  GUM_ELF_ARM_TLS_CALL,
  GUM_ELF_ARM_TLS_DESCSEQ,
  GUM_ELF_ARM_THM_TLS_CALL,
  GUM_ELF_ARM_PLT32_ABS,
  GUM_ELF_ARM_GOT_ABS,
  GUM_ELF_ARM_GOT_PREL,
  GUM_ELF_ARM_GOT_BREL12,
  GUM_ELF_ARM_GOTOFF12,
  GUM_ELF_ARM_GOTRELAX,
  GUM_ELF_ARM_GNU_VTENTRY,
  GUM_ELF_ARM_GNU_VTINHERIT,
  GUM_ELF_ARM_THM_PC11,
  GUM_ELF_ARM_THM_PC9,
  GUM_ELF_ARM_TLS_GD32,
  GUM_ELF_ARM_TLS_LDM32,
  GUM_ELF_ARM_TLS_LDO32,
  GUM_ELF_ARM_TLS_IE32,
  GUM_ELF_ARM_TLS_LE32,
  GUM_ELF_ARM_TLS_LDO12,
  GUM_ELF_ARM_TLS_LE12,
  GUM_ELF_ARM_TLS_IE12GP,
  GUM_ELF_ARM_ME_TOO = 128,
  GUM_ELF_ARM_THM_TLS_DESCSEQ,
  GUM_ELF_ARM_THM_TLS_DESCSEQ16 = 129,
  GUM_ELF_ARM_THM_TLS_DESCSEQ32,
  GUM_ELF_ARM_THM_GOT_BREL12,
  GUM_ELF_ARM_IRELATIVE = 160,
  GUM_ELF_ARM_RXPC25 = 249,
  GUM_ELF_ARM_RSBREL32,
  GUM_ELF_ARM_THM_RPC22,
  GUM_ELF_ARM_RREL32,
  GUM_ELF_ARM_RABS22,
  GUM_ELF_ARM_RPC24,
  GUM_ELF_ARM_RBASE,
} GumElfArmRelocation;

typedef enum {
  GUM_ELF_ARM64_NONE,
  GUM_ELF_ARM64_P32_ABS32,
  GUM_ELF_ARM64_P32_COPY = 180,
  GUM_ELF_ARM64_P32_GLOB_DAT,
  GUM_ELF_ARM64_P32_JUMP_SLOT,
  GUM_ELF_ARM64_P32_RELATIVE,
  GUM_ELF_ARM64_P32_TLS_DTPMOD,
  GUM_ELF_ARM64_P32_TLS_DTPREL,
  GUM_ELF_ARM64_P32_TLS_TPREL,
  GUM_ELF_ARM64_P32_TLSDESC,
  GUM_ELF_ARM64_P32_IRELATIVE,
  GUM_ELF_ARM64_ABS64 = 257,
  GUM_ELF_ARM64_ABS32,
  GUM_ELF_ARM64_ABS16,
  GUM_ELF_ARM64_PREL64,
  GUM_ELF_ARM64_PREL32,
  GUM_ELF_ARM64_PREL16,
  GUM_ELF_ARM64_MOVW_UABS_G0,
  GUM_ELF_ARM64_MOVW_UABS_G0_NC,
  GUM_ELF_ARM64_MOVW_UABS_G1,
  GUM_ELF_ARM64_MOVW_UABS_G1_NC,
  GUM_ELF_ARM64_MOVW_UABS_G2,
  GUM_ELF_ARM64_MOVW_UABS_G2_NC,
  GUM_ELF_ARM64_MOVW_UABS_G3,
  GUM_ELF_ARM64_MOVW_SABS_G0,
  GUM_ELF_ARM64_MOVW_SABS_G1,
  GUM_ELF_ARM64_MOVW_SABS_G2,
  GUM_ELF_ARM64_LD_PREL_LO19,
  GUM_ELF_ARM64_ADR_PREL_LO21,
  GUM_ELF_ARM64_ADR_PREL_PG_HI21,
  GUM_ELF_ARM64_ADR_PREL_PG_HI21_NC,
  GUM_ELF_ARM64_ADD_ABS_LO12_NC,
  GUM_ELF_ARM64_LDST8_ABS_LO12_NC,
  GUM_ELF_ARM64_TSTBR14,
  GUM_ELF_ARM64_CONDBR19,
  GUM_ELF_ARM64_JUMP26 = 282,
  GUM_ELF_ARM64_CALL26,
  GUM_ELF_ARM64_LDST16_ABS_LO12_NC,
  GUM_ELF_ARM64_LDST32_ABS_LO12_NC,
  GUM_ELF_ARM64_LDST64_ABS_LO12_NC,
  GUM_ELF_ARM64_MOVW_PREL_G0,
  GUM_ELF_ARM64_MOVW_PREL_G0_NC,
  GUM_ELF_ARM64_MOVW_PREL_G1,
  GUM_ELF_ARM64_MOVW_PREL_G1_NC,
  GUM_ELF_ARM64_MOVW_PREL_G2,
  GUM_ELF_ARM64_MOVW_PREL_G2_NC,
  GUM_ELF_ARM64_MOVW_PREL_G3,
  GUM_ELF_ARM64_LDST128_ABS_LO12_NC = 299,
  GUM_ELF_ARM64_MOVW_GOTOFF_G0,
  GUM_ELF_ARM64_MOVW_GOTOFF_G0_NC,
  GUM_ELF_ARM64_MOVW_GOTOFF_G1,
  GUM_ELF_ARM64_MOVW_GOTOFF_G1_NC,
  GUM_ELF_ARM64_MOVW_GOTOFF_G2,
  GUM_ELF_ARM64_MOVW_GOTOFF_G2_NC,
  GUM_ELF_ARM64_MOVW_GOTOFF_G3,
  GUM_ELF_ARM64_GOTREL64,
  GUM_ELF_ARM64_GOTREL32,
  GUM_ELF_ARM64_GOT_LD_PREL19,
  GUM_ELF_ARM64_LD64_GOTOFF_LO15,
  GUM_ELF_ARM64_ADR_GOT_PAGE,
  GUM_ELF_ARM64_LD64_GOT_LO12_NC,
  GUM_ELF_ARM64_LD64_GOTPAGE_LO15,
  GUM_ELF_ARM64_TLSGD_ADR_PREL21 = 512,
  GUM_ELF_ARM64_TLSGD_ADR_PAGE21,
  GUM_ELF_ARM64_TLSGD_ADD_LO12_NC,
  GUM_ELF_ARM64_TLSGD_MOVW_G1,
  GUM_ELF_ARM64_TLSGD_MOVW_G0_NC,
  GUM_ELF_ARM64_TLSLD_ADR_PREL21,
  GUM_ELF_ARM64_TLSLD_ADR_PAGE21,
  GUM_ELF_ARM64_TLSLD_ADD_LO12_NC,
  GUM_ELF_ARM64_TLSLD_MOVW_G1,
  GUM_ELF_ARM64_TLSLD_MOVW_G0_NC,
  GUM_ELF_ARM64_TLSLD_LD_PREL19,
  GUM_ELF_ARM64_TLSLD_MOVW_DTPREL_G2,
  GUM_ELF_ARM64_TLSLD_MOVW_DTPREL_G1,
  GUM_ELF_ARM64_TLSLD_MOVW_DTPREL_G1_NC,
  GUM_ELF_ARM64_TLSLD_MOVW_DTPREL_G0,
  GUM_ELF_ARM64_TLSLD_MOVW_DTPREL_G0_NC,
  GUM_ELF_ARM64_TLSLD_ADD_DTPREL_HI12,
  GUM_ELF_ARM64_TLSLD_ADD_DTPREL_LO12,
  GUM_ELF_ARM64_TLSLD_ADD_DTPREL_LO12_NC,
  GUM_ELF_ARM64_TLSLD_LDST8_DTPREL_LO12,
  GUM_ELF_ARM64_TLSLD_LDST8_DTPREL_LO12_NC,
  GUM_ELF_ARM64_TLSLD_LDST16_DTPREL_LO12,
  GUM_ELF_ARM64_TLSLD_LDST16_DTPREL_LO12_NC,
  GUM_ELF_ARM64_TLSLD_LDST32_DTPREL_LO12,
  GUM_ELF_ARM64_TLSLD_LDST32_DTPREL_LO12_NC,
  GUM_ELF_ARM64_TLSLD_LDST64_DTPREL_LO12,
  GUM_ELF_ARM64_TLSLD_LDST64_DTPREL_LO12_NC,
  GUM_ELF_ARM64_TLSIE_MOVW_GOTTPREL_G1,
  GUM_ELF_ARM64_TLSIE_MOVW_GOTTPREL_G0_NC,
  GUM_ELF_ARM64_TLSIE_ADR_GOTTPREL_PAGE21,
  GUM_ELF_ARM64_TLSIE_LD64_GOTTPREL_LO12_NC,
  GUM_ELF_ARM64_TLSIE_LD_GOTTPREL_PREL19,
  GUM_ELF_ARM64_TLSLE_MOVW_TPREL_G2,
  GUM_ELF_ARM64_TLSLE_MOVW_TPREL_G1,
  GUM_ELF_ARM64_TLSLE_MOVW_TPREL_G1_NC,
  GUM_ELF_ARM64_TLSLE_MOVW_TPREL_G0,
  GUM_ELF_ARM64_TLSLE_MOVW_TPREL_G0_NC,
  GUM_ELF_ARM64_TLSLE_ADD_TPREL_HI12,
  GUM_ELF_ARM64_TLSLE_ADD_TPREL_LO12,
  GUM_ELF_ARM64_TLSLE_ADD_TPREL_LO12_NC,
  GUM_ELF_ARM64_TLSLE_LDST8_TPREL_LO12,
  GUM_ELF_ARM64_TLSLE_LDST8_TPREL_LO12_NC,
  GUM_ELF_ARM64_TLSLE_LDST16_TPREL_LO12,
  GUM_ELF_ARM64_TLSLE_LDST16_TPREL_LO12_NC,
  GUM_ELF_ARM64_TLSLE_LDST32_TPREL_LO12,
  GUM_ELF_ARM64_TLSLE_LDST32_TPREL_LO12_NC,
  GUM_ELF_ARM64_TLSLE_LDST64_TPREL_LO12,
  GUM_ELF_ARM64_TLSLE_LDST64_TPREL_LO12_NC,
  GUM_ELF_ARM64_TLSDESC_LD_PREL19,
  GUM_ELF_ARM64_TLSDESC_ADR_PREL21,
  GUM_ELF_ARM64_TLSDESC_ADR_PAGE21,
  GUM_ELF_ARM64_TLSDESC_LD64_LO12,
  GUM_ELF_ARM64_TLSDESC_ADD_LO12,
  GUM_ELF_ARM64_TLSDESC_OFF_G1,
  GUM_ELF_ARM64_TLSDESC_OFF_G0_NC,
  GUM_ELF_ARM64_TLSDESC_LDR,
  GUM_ELF_ARM64_TLSDESC_ADD,
  GUM_ELF_ARM64_TLSDESC_CALL,
  GUM_ELF_ARM64_TLSLE_LDST128_TPREL_LO12,
  GUM_ELF_ARM64_TLSLE_LDST128_TPREL_LO12_NC,
  GUM_ELF_ARM64_TLSLD_LDST128_DTPREL_LO12,
  GUM_ELF_ARM64_TLSLD_LDST128_DTPREL_LO12_NC,
  GUM_ELF_ARM64_COPY = 1024,
  GUM_ELF_ARM64_GLOB_DAT,
  GUM_ELF_ARM64_JUMP_SLOT,
  GUM_ELF_ARM64_RELATIVE,
  GUM_ELF_ARM64_TLS_DTPMOD,
  GUM_ELF_ARM64_TLS_DTPREL,
  GUM_ELF_ARM64_TLS_TPREL,
  GUM_ELF_ARM64_TLSDESC,
  GUM_ELF_ARM64_IRELATIVE,
} GumElfArm64Relocation;

typedef enum {
  GUM_ELF_MIPS_NONE,
  GUM_ELF_MIPS_16,
  GUM_ELF_MIPS_32,
  GUM_ELF_MIPS_REL32,
  GUM_ELF_MIPS_26,
  GUM_ELF_MIPS_HI16,
  GUM_ELF_MIPS_LO16,
  GUM_ELF_MIPS_GPREL16,
  GUM_ELF_MIPS_LITERAL,
  GUM_ELF_MIPS_GOT16,
  GUM_ELF_MIPS_PC16,
  GUM_ELF_MIPS_CALL16,
  GUM_ELF_MIPS_GPREL32,
  GUM_ELF_MIPS_SHIFT5 = 16,
  GUM_ELF_MIPS_SHIFT6,
  GUM_ELF_MIPS_64,
  GUM_ELF_MIPS_GOT_DISP,
  GUM_ELF_MIPS_GOT_PAGE,
  GUM_ELF_MIPS_GOT_OFST,
  GUM_ELF_MIPS_GOT_HI16,
  GUM_ELF_MIPS_GOT_LO16,
  GUM_ELF_MIPS_SUB,
  GUM_ELF_MIPS_INSERT_A,
  GUM_ELF_MIPS_INSERT_B,
  GUM_ELF_MIPS_DELETE,
  GUM_ELF_MIPS_HIGHER,
  GUM_ELF_MIPS_HIGHEST,
  GUM_ELF_MIPS_CALL_HI16,
  GUM_ELF_MIPS_CALL_LO16,
  GUM_ELF_MIPS_SCN_DISP,
  GUM_ELF_MIPS_REL16,
  GUM_ELF_MIPS_ADD_IMMEDIATE,
  GUM_ELF_MIPS_PJUMP,
  GUM_ELF_MIPS_RELGOT,
  GUM_ELF_MIPS_JALR,
  GUM_ELF_MIPS_TLS_DTPMOD32,
  GUM_ELF_MIPS_TLS_DTPREL32,
  GUM_ELF_MIPS_TLS_DTPMOD64,
  GUM_ELF_MIPS_TLS_DTPREL64,
  GUM_ELF_MIPS_TLS_GD,
  GUM_ELF_MIPS_TLS_LDM,
  GUM_ELF_MIPS_TLS_DTPREL_HI16,
  GUM_ELF_MIPS_TLS_DTPREL_LO16,
  GUM_ELF_MIPS_TLS_GOTTPREL,
  GUM_ELF_MIPS_TLS_TPREL32,
  GUM_ELF_MIPS_TLS_TPREL64,
  GUM_ELF_MIPS_TLS_TPREL_HI16,
  GUM_ELF_MIPS_TLS_TPREL_LO16,
  GUM_ELF_MIPS_GLOB_DAT,
  GUM_ELF_MIPS_COPY = 126,
  GUM_ELF_MIPS_JUMP_SLOT,
} GumElfMipsRelocation;

typedef struct _GumElfSegmentDetails GumElfSegmentDetails;
typedef struct _GumElfSectionDetails GumElfSectionDetails;
typedef struct _GumElfRelocationDetails GumElfRelocationDetails;
typedef struct _GumElfDynamicEntryDetails GumElfDynamicEntryDetails;
typedef struct _GumElfSymbolDetails GumElfSymbolDetails;

typedef gboolean (* GumFoundElfSegmentFunc) (
    const GumElfSegmentDetails * details, gpointer user_data);
typedef gboolean (* GumFoundElfSectionFunc) (
    const GumElfSectionDetails * details, gpointer user_data);
typedef gboolean (* GumFoundElfRelocationFunc) (
    const GumElfRelocationDetails * details, gpointer user_data);
typedef gboolean (* GumFoundElfDynamicEntryFunc) (
    const GumElfDynamicEntryDetails * details, gpointer user_data);
typedef gboolean (* GumFoundElfSymbolFunc) (const GumElfSymbolDetails * details,
    gpointer user_data);

struct _GumElfSegmentDetails
{
  GumAddress vm_address;
  guint64 vm_size;
  guint64 file_offset;
  guint64 file_size;
  GumPageProtection protection;
};

struct _GumElfSectionDetails
{
  const gchar * id;
  const gchar * name;
  GumElfSectionType type;
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

struct _GumElfRelocationDetails
{
  GumAddress address;
  guint32 type;
  const GumElfSymbolDetails * symbol;
  gint64 addend;
  const GumElfSectionDetails * parent;
};

struct _GumElfDynamicEntryDetails
{
  GumElfDynamicTag tag;
  guint64 val;
};

struct _GumElfSymbolDetails
{
  const gchar * name;
  GumAddress address;
  gsize size;
  GumElfSymbolType type;
  GumElfSymbolBind bind;
  guint16 shdr_index;
  const GumElfSectionDetails * section;
};

GUM_API GumElfModule * gum_elf_module_new_from_file (const gchar * path,
    GError ** error);
GUM_API GumElfModule * gum_elf_module_new_from_blob (GBytes * blob,
    GError ** error);
GUM_API GumElfModule * gum_elf_module_new_from_memory (const gchar * path,
    GumAddress base_address, GError ** error);

GUM_API gboolean gum_elf_module_load (GumElfModule * self, GError ** error);

GUM_API GumElfType gum_elf_module_get_etype (GumElfModule * self);
GUM_API guint gum_elf_module_get_pointer_size (GumElfModule * self);
GUM_API gint gum_elf_module_get_byte_order (GumElfModule * self);
GUM_API GumElfOSABI gum_elf_module_get_os_abi (GumElfModule * self);
GUM_API guint8 gum_elf_module_get_os_abi_version (GumElfModule * self);
GUM_API GumElfMachine gum_elf_module_get_machine (GumElfModule * self);
GUM_API GumAddress gum_elf_module_get_base_address (GumElfModule * self);
GUM_API GumAddress gum_elf_module_get_preferred_address (GumElfModule * self);
GUM_API guint64 gum_elf_module_get_mapped_size (GumElfModule * self);
GUM_API GumAddress gum_elf_module_get_entrypoint (GumElfModule * self);
GUM_API const gchar * gum_elf_module_get_interpreter (GumElfModule * self);
GUM_API const gchar * gum_elf_module_get_source_path (GumElfModule * self);
GUM_API GBytes * gum_elf_module_get_source_blob (GumElfModule * self);
GUM_API GumElfSourceMode gum_elf_module_get_source_mode (GumElfModule * self);
GUM_API gconstpointer gum_elf_module_get_file_data (GumElfModule * self,
    gsize * size);

GUM_API void gum_elf_module_enumerate_segments (GumElfModule * self,
    GumFoundElfSegmentFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_sections (GumElfModule * self,
    GumFoundElfSectionFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_relocations (GumElfModule * self,
    GumFoundElfRelocationFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_dynamic_entries (GumElfModule * self,
    GumFoundElfDynamicEntryFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_imports (GumElfModule * self,
    GumFoundImportFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_exports (GumElfModule * self,
    GumFoundExportFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_dynamic_symbols (GumElfModule * self,
    GumFoundElfSymbolFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_symbols (GumElfModule * self,
    GumFoundElfSymbolFunc func, gpointer user_data);
GUM_API void gum_elf_module_enumerate_dependencies (GumElfModule * self,
    GumFoundDependencyFunc func, gpointer user_data);

GUM_API GumAddress gum_elf_module_translate_to_offline (GumElfModule * self,
    GumAddress online_address);
GUM_API GumAddress gum_elf_module_translate_to_online (GumElfModule * self,
    GumAddress offline_address);

GUM_API gboolean gum_elf_module_maybe_extract_from_apk (const gchar * path,
    GBytes ** file_bytes);

G_END_DECLS

#endif
