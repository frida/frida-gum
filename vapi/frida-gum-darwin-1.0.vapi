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
	public void enumerate_ranges (Port task, Gum.PageProtection prot, Gum.FoundRangeFunc func);

	public void enumerate_imports (Port task, string module_name, Gum.Module.FoundImportFunc func);
	public void enumerate_exports (Port task, string module_name, Gum.Module.FoundExportFunc func);
	public void enumerate_symbols (Port task, string module_name, Gum.Module.FoundSymbolFunc func);

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
