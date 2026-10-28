[CCode (cheader_filename = "gum/gumwindows.h")]
namespace Gum.Windows {
	public Gum.CpuType query_native_cpu_type ();
	public Gum.CpuType cpu_type_from_pid (uint pid) throws Gum.Error;

	public GLib.Bytes bytes_new_from_section (void * section, uint64 offset, size_t size) throws Gum.Error;

	[CCode (cheader_filename = "gum/gumdbghelp.h", cname = "gum_dbghelp_impl_use_modules")]
	public void use_dbghelp_modules (void * dbghelp, void * symsrv);

	public class ModuleResolver : GLib.Object, Gum.ModuleResolver {
		public ModuleResolver (void * process);
	}
}
