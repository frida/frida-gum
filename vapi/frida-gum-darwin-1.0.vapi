[CCode (cheader_filename = "gum/gumdarwin.h")]
namespace Gum.Darwin {
	public bool check_xnu_version (uint major, uint minor, uint micro);

	public uint8[]? read (Gum.DarwinPort task, Gum.Address address, size_t len);
	public bool write (Gum.DarwinPort task, Gum.Address address, uint8[] bytes);

	public bool cpu_type_from_pid (Posix.pid_t pid, out Gum.CpuType cpu_type);
	public bool query_ptrauth_support (Gum.DarwinPort task, out Gum.PtrauthSupport ptrauth_support);
	public bool query_page_size (Gum.DarwinPort task, out uint page_size);
	public unowned string query_sysroot ();
	public bool query_all_image_infos (Gum.DarwinPort task, out Gum.Darwin.AllImageInfos infos);
	public bool query_mapped_address (Gum.DarwinPort task, Gum.Address address, out Gum.Darwin.MappingDetails details);

	public Gum.Address find_entrypoint (Gum.DarwinPort task);

	public void enumerate_threads (Gum.DarwinPort task, Gum.FoundThreadFunc func);
	public void enumerate_modules (Gum.DarwinPort task, Gum.FoundModuleFunc func);
	public void enumerate_modules_forensically (Gum.DarwinPort task, Gum.FoundModuleFunc func);
	public void enumerate_ranges (Gum.DarwinPort task, Gum.PageProtection prot, Gum.FoundRangeFunc func);

	public void enumerate_imports (Gum.DarwinPort task, string module_name, Gum.FoundImportFunc func);
	public void enumerate_exports (Gum.DarwinPort task, string module_name, Gum.FoundExportFunc func);
	public void enumerate_symbols (Gum.DarwinPort task, string module_name, Gum.FoundSymbolFunc func);

	public struct AllImageInfos {
		int format;

		Gum.Address info_array_address;
		size_t info_array_count;
		size_t info_array_size;

		Gum.Address notification_address;

		bool libsystem_initialized;

		Gum.Address dyld_image_load_address;
	}

	public struct MappingDetails {
		unowned string path;

		uint64 offset;
		uint64 size;
	}

	public class Symbolicator : GLib.Object {
		public Symbolicator.with_path (string path, Gum.CpuType cpu_type) throws GLib.Error;
		public Symbolicator.with_task (Gum.DarwinPort task) throws GLib.Error;

		public bool load () throws Gum.Error;

		public bool details_from_address (Gum.Address address, out Gum.DebugSymbolDetails details);
		public string? name_from_address (Gum.Address address);

		public Gum.Address find_function (string name);
		public Gum.Address[] find_functions_named (string name);
		public Gum.Address[] find_functions_matching (string str);
	}

	[CCode (cname = "mach_task_self")]
	public Gum.DarwinPort mach_task_self ();
	[CCode (cname = "task_for_pid")]
	public Status task_for_pid (Gum.DarwinPort target_tport, int pid, out Gum.DarwinPort task);

	[CCode (cname = "kern_return_t", cprefix = "KERN_", has_type_id = false)]
	public enum Status {
		SUCCESS
	}
}
