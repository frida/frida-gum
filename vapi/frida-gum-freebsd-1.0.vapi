[CCode (cheader_filename = "gum/gumfreebsd.h")]
namespace Gum.Freebsd {
	public string query_program_path (Posix.pid_t pid) throws Gum.Error;
	public void enumerate_ranges (Posix.pid_t pid, Gum.PageProtection prot, Gum.FoundRangeFunc func);
}
