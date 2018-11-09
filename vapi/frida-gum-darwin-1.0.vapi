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
		[NoAccessorMethod]
		public string? name {
			owned get;
			construct;
		}

		[NoAccessorMethod]
		public string? uuid {
			owned get;
		}

		public Module.from_file (string path, Port task, Gum.CpuType cpu_type, uint page_size, GLib.MappedFile? cache_file = null) throws GLib.Error;
		public Module.from_blob (GLib.Bytes blob, Port task, Gum.CpuType cpu_type, uint page_size) throws GLib.Error;
		public Module.from_memory (string? name, Port task, Gum.CpuType cpu_type, uint page_size, Gum.Address base_address) throws GLib.Error;
	}

	public class Symbolicator : GLib.Object, GLib.Initable {
		public Symbolicator (Port task) throws GLib.Error;

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
}
