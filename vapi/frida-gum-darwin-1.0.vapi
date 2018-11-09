[CCode (cheader_filename = "gum/gumdarwin.h")]
namespace Gum.Darwin {
	public bool is_ios9_or_newer ();

	public uint8[]? read (Port task, Gum.Address address, size_t len);
	public bool write (Port task, Gum.Address address, uint8[] bytes);

	public bool cpu_type_from_pid (Posix.pid_t pid, out Gum.CpuType cpu_type);
	public bool query_page_size (Port task, out uint page_size);

	public Gum.Address find_entrypoint (Port task);

	public void enumerate_threads (Port task, Gum.Process.FoundThreadFunc func);
	public void enumerate_modules (Port task, Gum.Process.FoundModuleFunc func);
	public void enumerate_modules_forensically (Port task, Gum.Process.FoundModuleFunc func);
	public void enumerate_ranges (Port task, Gum.PageProtection prot, Gum.FoundRangeFunc func);

	public void enumerate_imports (Port task, string module_name, Gum.Module.FoundImportFunc func);
	public void enumerate_exports (Port task, string module_name, Gum.Module.FoundExportFunc func);
	public void enumerate_symbols (Port task, string module_name, Gum.Module.FoundSymbolFunc func);

	public class Module : GLib.Object, GLib.Initable {
		public string? name;
		public string? uuid;

		public Port task;
		public bool is_local;
		public bool is_kernel;
		public Gum.CpuType cpu_type;
		public size_t pointer_size;
		public size_t page_size;
		public Gum.Address base_address;
		public string? source_path;
		public GLib.Bytes? source_blob;
		public GLib.MappedFile? cache_file;

		public ModuleImage image;

		public void * info;
		public void * symtab;
		public void * dysymtab;

		public Gum.Address preferred_address;

		public GLib.Array<Segment> segments;

		public bool lacks_exports_for_reexports {
			get;
		}

		public Gum.Address slide {
			get;
		}

		public Module.from_file (string path, Port task, Gum.CpuType cpu_type, uint page_size, GLib.MappedFile? cache_file = null) throws GLib.Error;
		public Module.from_blob (GLib.Bytes blob, Port task, Gum.CpuType cpu_type, uint page_size) throws GLib.Error;
		public Module.from_memory (string? name, Port task, Gum.CpuType cpu_type, uint page_size, Gum.Address base_address) throws GLib.Error;

		public bool resolve_export (string symbol, out ExportDetails details);
		public Gum.Address resolve_symbol_address (string symbol);
		public void enumerate_imports (Gum.Module.FoundImportFunc func);
		public void enumerate_exports (FoundExportFunc func);
		public void enumerate_symbols (FoundSymbolFunc func);
		public void enumerate_sections (FoundSectionFunc func);
		public bool is_address_in_text_section (Gum.Address address);
		public void enumerate_rebases (FoundRebaseFunc func);
		public void enumerate_binds (FoundBindFunc func);
		public void enumerate_lazy_binds (FoundBindFunc func);
		public void enumerate_init_pointers (FoundInitPointersFunc func);
		public void enumerate_term_pointers (FoundTermPointersFunc func);
		public unowned string? get_dependency_by_ordinal (int ordinal);

		public delegate bool FoundExportFunc (ExportDetails details);
		public delegate bool FoundSymbolFunc (SymbolDetails details);
		public delegate bool FoundSectionFunc (SectionDetails details);
		public delegate bool FoundRebaseFunc (RebaseDetails details);
		public delegate bool FoundBindFunc (BindDetails details);
		public delegate bool FoundInitPointersFunc (InitPointersDetails details);
		public delegate bool FoundTermPointersFunc (TermPointersDetails details);
	}

	[Compact]
	public class ModuleImage {
		public void * data;
		public uint64 size;
		public void * linkedit;

		public uint64 source_offset;
		public uint64 source_size;
		public uint64 shared_offset;
		public uint64 shared_size;
		public GLib.Array<ModuleImageSegment> shared_segments;

		public GLib.Bytes bytes;
		public void * malloc_data;
	}

	public struct ModuleImageSegment {
		public uint64 offset;
		public uint64 size;
		public int protection;
	}

	public struct SectionDetails {
		public string segment_name;
		public string section_name;
		public Gum.Address vm_address;
		public uint64 size;
		public Protection protection;
		public uint32 file_offset;
		public uint32 flags;
	}

	public struct RebaseDetails {
		public Segment? segment;
		public uint64 offset;
		public uint8 type;
		public Gum.Address slide;
	}

	public struct BindDetails {
		public Segment? segment;
		public uint64 offset;
		public uint8 type;
		public int library_ordinal;
		public string symbol_name;
		public uint8 symbol_flags;
		public int64 addend;
	}

	public struct InitPointersDetails {
		public Gum.Address address;
		public uint64 count;
	}

	public struct TermPointersDetails {
		public Gum.Address address;
		public uint64 count;
	}

	public struct Segment {
		public string name;
		public Gum.Address vm_address;
		public uint64 vm_size;
		public uint64 file_offset;
		public uint64 file_size;
		public Protection protection;
	}

	public struct ExportDetails {
		public string name;
		public uint64 flags;

		public uint64 offset;

		public uint64 stub;
		public uint64 resolver;

		public int reexport_library_ordinal;
		public string reexport_symbol;
	}

	public struct SymbolDetails {
		public string name;
		public Gum.Address address;

		public uint8 type;
		public uint8 section;
		public uint16 description;
	}

	public class Symbolicator : GLib.Object, GLib.Initable {
		public Symbolicator.with_path (string path, Gum.CpuType cpu_type) throws GLib.Error;
		public Symbolicator.with_task (Port task) throws GLib.Error;

		public bool details_from_address (Gum.Address address, out Gum.DebugSymbolDetails details);
		public string? name_from_address (Gum.Address address);

		public Gum.Address find_function (string name);
		public Gum.Address[] find_functions_named (string name);
		public Gum.Address[] find_functions_matching (string str);
	}

	[CCode (cname = "mach_task_self")]
	public Port mach_task_self ();
	[CCode (cname = "task_for_pid")]
	public Status task_for_pid (Port target_tport, int pid, out Port task);

	[CCode (cname = "kern_return_t", cprefix = "KERN_", has_type_id = false)]
	public enum Status {
		SUCCESS
	}

	[CCode (cname = "mach_port_t", has_type_id = false)]
	public struct Port : uint {
	}

	[CCode (cname = "vm_prot_t", has_type_id = false)]
	public struct Protection : int {
	}
}
