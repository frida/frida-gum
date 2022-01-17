namespace Gum {
	[CCode (cheader_filename = "gum/gumelfmodule.h")]
	public class ElfModule : GLib.Object {
		public ElfModule.from_file (string path) throws Gum.Error;
		public ElfModule.from_memory (string path, Gum.Address base_address) throws Gum.Error;

		public bool load () throws Gum.Error;

		public string name { get; }
		public string path { get; }
		public Gum.Address base_address { get; }
		public Gum.Address preferred_address { get; }
		public Gum.Address entrypoint { get; }
		public void * elf { get; }
		public bool has_interp { get; }

		public void enumerate_dependencies (Gum.FoundElfDependencyFunc func);
		public void enumerate_imports (Gum.FoundImportFunc func);
		public void enumerate_exports (Gum.FoundExportFunc func);
		public void enumerate_dynamic_symbols (Gum.FoundElfSymbolFunc func);
		public void enumerate_symbols (Gum.FoundElfSymbolFunc func);
		public void enumerate_dynamic_entries (Gum.FoundElfDynamicEntryFunc func);
		public void enumerate_sections (Gum.FoundElfSectionFunc func);

		public Gum.Address translate_to_offline (Gum.Address online_address);
		public Gum.Address translate_to_online (Gum.Address offline_address);
	}

	public delegate bool FoundElfDependencyFunc (Gum.ElfDependencyDetails details);
	public delegate bool FoundElfSymbolFunc (Gum.ElfSymbolDetails details);
	public delegate bool FoundElfDynamicEntryFunc (Gum.ElfDynamicEntryDetails details);
	public delegate bool FoundElfSectionFunc (Gum.ElfSectionDetails details);

	public struct ElfDependencyDetails {
		public string name;
	}

	public struct ElfSymbolDetails {
		public string name;
		public Gum.Address address;
		public size_t size;
		public Gum.ElfSymbolType type;
		public Gum.ElfSymbolBind bind;
		public uint16 section_header_index;
	}

	public struct ElfDynamicEntryDetails {
		public Gum.ElfDynamicTag tag;
		public uint64 val;
	}

	public struct ElfSectionDetails {
		public string name;
		public uint32 type;
		public uint64 flags;
		public Gum.Address address;
		public uint64 offset;
		public size_t size;
		public uint32 link;
		public uint32 info;
		public uint64 alignment;
		public uint64 entry_size;
		public Gum.PageProtection protection;
	}

	[CCode (cprefix = "GUM_ELF_SYMBOL_")]
	public enum ElfSymbolType {
		NOTYPE,
		OBJECT,
		FUNC,
		SECTION,
		FILE,
		COMMON,
		TLS,
		NUM,
		LOOS,
		GNU_IFUNC,
		HIOS,
		LOPROC,
		SPARC_REGISTER,
		HIPROC,
	}

	[CCode (cprefix = "GUM_ELF_BIND_")]
	public enum ElfSymbolBind {
		LOCAL,
		GLOBAL,
		WEAK,
		LOOS,
		GNU_UNIQUE,
		HIOS,
		LOPROC,
		HIPROC,
	}

	[CCode (cprefix = "GUM_ELF_DYNAMIC_")]
	public enum ElfDynamicTag {
		NULL,
		NEEDED,
		PLTRELSZ,
		PLTGOT,
		HASH,
		STRTAB,
		SYMTAB,
		RELA,
		RELASZ,
		RELAENT,
		STRSZ,
		SYMENT,
		INIT,
		FINI,
		SONAME,
		RPATH,
		SYMBOLIC,
		REL,
		RELSZ,
		RELENT,
		PLTREL,
		DEBUG,
		TEXTREL,
		JMPREL,
		BIND_NOW,
		INIT_ARRAY,
		FINI_ARRAY,
		INIT_ARRAYSZ,
		FINI_ARRAYSZ,
		RUNPATH,
		FLAGS,
		ENCODING,
		PREINIT_ARRAY,
		PREINIT_ARRAYSZ,
		MAXPOSTAGS,
		LOOS,
		SUNW_AUXILIARY,
		SUNW_RTLDINF,
		SUNW_FILTER,
		SUNW_CAP,
		SUNW_ASLR,
		HIOS,

		VALRNGLO,
		GNU_PRELINKED,
		GNU_CONFLICTSZ,
		GNU_LIBLISTSZ,
		CHECKSUM,
		PLTPADSZ,
		MOVEENT,
		MOVESZ,
		FEATURE,
		FEATURE_1,
		POSFLAG_1,

		SYMINSZ,
		SYMINENT,
		VALRNGHI,

		ADDRRNGLO,
		GNU_HASH,
		TLSDESC_PLT,
		TLSDESC_GOT,
		GNU_CONFLICT,
		GNU_LIBLIST,
		CONFIG,
		DEPAUDIT,
		AUDIT,
		PLTPAD,
		MOVETAB,
		SYMINFO,
		ADDRRNGHI,

		VERSYM,
		RELACOUNT,
		RELCOUNT,
		FLAGS_1,
		VERDEF,
		VERDEFNUM,
		VERNEED,
		VERNEEDNUM,

		LOPROC,

		ARM_SYMTABSZ,
		ARM_PREEMPTMAP,

		SPARC_REGISTER,
		DEPRECATED_SPARC_REGISTER,

		MIPS_RLD_VERSION,
		MIPS_TIME_STAMP,
		MIPS_ICHECKSUM,
		MIPS_IVERSION,
		MIPS_FLAGS,
		MIPS_BASE_ADDRESS,
		MIPS_CONFLICT,
		MIPS_LIBLIST,
		MIPS_LOCAL_GOTNO,
		MIPS_CONFLICTNO,
		MIPS_LIBLISTNO,
		MIPS_SYMTABNO,
		MIPS_UNREFEXTNO,
		MIPS_GOTSYM,
		MIPS_HIPAGENO,
		MIPS_RLD_MAP,
		MIPS_DELTA_CLASS,
		MIPS_DELTA_CLASS_NO,
		MIPS_DELTA_INSTANCE,
		MIPS_DELTA_INSTANCE_NO,
		MIPS_DELTA_RELOC,
		MIPS_DELTA_RELOC_NO,
		MIPS_DELTA_SYM,
		MIPS_DELTA_SYM_NO,
		MIPS_DELTA_CLASSSYM,
		MIPS_DELTA_CLASSSYM_NO,
		MIPS_CXX_FLAGS,
		MIPS_PIXIE_INIT,
		MIPS_SYMBOL_LIB,
		MIPS_LOCALPAGE_GOTIDX,
		MIPS_LOCAL_GOTIDX,
		MIPS_HIDDEN_GOTIDX,
		MIPS_PROTECTED_GOTIDX,
		MIPS_OPTIONS,
		MIPS_INTERFACE,
		MIPS_DYNSTR_ALIGN,
		MIPS_INTERFACE_SIZE,
		MIPS_RLD_TEXT_RESOLVE_ADDR,
		MIPS_PERF_SUFFIX,
		MIPS_COMPACT_SIZE,
		MIPS_GP_VALUE,
		MIPS_AUX_DYNAMIC,
		MIPS_PLTGOT,
		MIPS_RLD_OBJ_UPDATE,
		MIPS_RWPLT,
		MIPS_RLD_MAP_REL,

		PPC_GOT,
		PPC_TLSOPT,

		PPC64_GLINK,
		PPC64_OPD,
		PPC64_OPDSZ,
		PPC64_TLSOPT,

		AUXILIARY,
		USED,
		FILTER,
		HIPROC,
	}
}
