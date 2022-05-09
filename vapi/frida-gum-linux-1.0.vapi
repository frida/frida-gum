[CCode (cheader_filename = "gum/gumlinux.h")]
namespace Gum.Linux {
	public Gum.CpuType cpu_type_from_file (string path) throws Gum.Error;
	public Gum.CpuType cpu_type_from_pid (Posix.pid_t pid) throws Gum.Error;
}
