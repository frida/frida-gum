[CCode (cheader_filename = "gum/gum.h")]
namespace Gum {
	public void init ();
	public void shutdown ();
	public void deinit ();

	public void init_embedded ();
	public void deinit_embedded ();

	public void prepare_to_fork ();
	public void recover_from_fork_in_parent ();
	public void recover_from_fork_in_child ();

	[CCode (cprefix = "GUM_CODE_SIGNING_")]
	public enum CodeSigningPolicy {
		OPTIONAL,
		REQUIRED
	}

	[CCode (cprefix = "GUM_CALL_")]
	public enum CallingConvention {
		CAPI,
		SYSAPI
	}

	[CCode (cprefix = "GUM_CPU_")]
	public enum CpuType {
		IA32,
		AMD64,
		ARM,
		ARM64,
		MIPS,
	}

	public class Interceptor : GLib.Object {
		public static Interceptor obtain ();

		public Gum.AttachReturn attach_listener (void * function_address, Gum.InvocationListener listener, void * listener_function_data = null);
		public void detach_listener (Gum.InvocationListener listener);

		public Gum.ReplaceReturn replace_function (void * function_address, void * replacement_function, void * replacement_function_data = null);
		public void revert_function (void * function_address);

		public void begin_transaction ();
		public void end_transaction ();
		public bool flush ();

		public static unowned Gum.InvocationContext get_current_invocation ();

		public void ignore_current_thread ();
		public void unignore_current_thread ();

		public void ignore_other_threads ();
		public void unignore_other_threads ();
	}

	[CCode (type_cname = "GumInvocationListenerInterface")]
	public interface InvocationListener : GLib.Object {
		public virtual void on_enter (Gum.InvocationContext context);
		public virtual void on_leave (Gum.InvocationContext context);
	}

	[Compact]
	public class InvocationContext {
		public void * function;
		public CpuContext * cpu_context;
		public int system_error;

		public void * backend;

		public Gum.PointCut get_point_cut ();

		public void * get_nth_argument (uint n);
		public void replace_nth_argument (uint n, void * val);
		public void * get_return_value ();
		public void replace_return_value (void * val);

		public void * get_return_address ();

		public uint get_thread_id ();
		public uint get_depth ();

		public void * get_listener_thread_data (size_t required_size);
		public void * get_listener_function_data ();
		public void * get_listener_function_invocation_data (size_t required_size);

		public void * get_replacement_function_data ();
	}

	[CCode (cprefix = "GUM_POINT_")]
	public enum PointCut {
		ENTER,
		LEAVE
	}

	public class MemoryAccessMonitor : GLib.Object {
		public MemoryAccessMonitor ();

		public void enable (Gum.MemoryRange range, Gum.MemoryAccessNotify func);
		public void disable ();
	}

	public delegate void MemoryAccessNotify (Gum.MemoryAccessMonitor monitor, Gum.MemoryAccessDetails details);

	public struct MemoryAccessDetails {
		public Gum.MemoryOperation operation;
		public void * from;
		public void * address;

		public uint page_index;
		public uint pages_completed;
		public uint pages_remaining;
	}

	[CCode (cprefix = "GUM_MEMOP_")]
	public enum MemoryOperation {
		READ,
		WRITE,
		EXECUTE
	}

	public class Stalker : GLib.Object {
		public static bool is_supported ();

		public Stalker ();

		public void exclude (Gum.MemoryRange range);

		public int get_trust_threshold ();
		public void set_trust_threshold (int trust_threshold);

		public void flush ();
		public void stop ();
		public bool garbage_collect ();

		public void follow_me (Gum.EventSink sink);
		public void unfollow_me ();
		public bool is_following_me ();

		public void follow (Gum.ThreadId thread_id, Gum.EventSink sink);
		public void unfollow (Gum.ThreadId thread_id);

		public Gum.Stalker.ProbeId add_call_probe (void * target_address, owned Gum.Stalker.CallProbeCallback callback);
		public void remove_call_probe (Gum.Stalker.ProbeId id);

		public struct ProbeId : uint {
		}

		public delegate void CallProbeCallback (Gum.CallSite site);
	}

	[CCode (type_cname = "GumEventSinkInterface")]
	public interface EventSink : GLib.Object {
		public abstract Gum.EventType query_mask ();
		public abstract void process (void * opaque_event);
	}

	public struct CallSite {
		public void * block_address;
		public void * stack_data;
		public CpuContext * cpu_context;
	}

	namespace Process {
		public Gum.CodeSigningPolicy get_code_signing_policy ();
		public void set_code_signing_policy (Gum.CodeSigningPolicy policy);
		public bool is_debugger_attached ();
		public Gum.ThreadId get_current_thread_id ();
		public bool modify_thread (Gum.ThreadId thread_id, Gum.Process.ModifyThreadFunc func);
		public void enumerate_threads (Gum.Process.FoundThreadFunc func);
		public void enumerate_modules (Gum.Process.FoundModuleFunc func);
		public void enumerate_ranges (Gum.PageProtection prot, Gum.FoundRangeFunc func);

		public delegate void ModifyThreadFunc (Gum.ThreadId thread_id, CpuContext * cpu_context);
		public delegate bool FoundThreadFunc (Gum.ThreadDetails details);
		public delegate bool FoundModuleFunc (Gum.ModuleDetails details);
	}

	namespace Thread {
		public uint try_get_ranges (Gum.MemoryRange[] ranges);
	}

	namespace Module {
		public bool ensure_initialized (string module_name);
		public void enumerate_imports (string module_name, Gum.Module.FoundImportFunc func);
		public void enumerate_exports (string module_name, Gum.Module.FoundExportFunc func);
		public void enumerate_symbols (string module_name, Gum.Module.FoundSymbolFunc func);
		public void enumerate_ranges (string module_name, Gum.PageProtection prot, Gum.FoundRangeFunc func);
		public void * find_base_address (string module_name);
		public void * find_export_by_name (string? module_name, string symbol_name);

		public delegate bool FoundImportFunc (Gum.ImportDetails details);
		public delegate bool FoundExportFunc (Gum.ExportDetails details);
		public delegate bool FoundSymbolFunc (Gum.SymbolDetails details);
	}

	namespace Memory {
		public uint8[] read (Address address, size_t len);
		public bool write (Address address, uint8[] bytes);
		public void scan (Gum.MemoryRange range, Gum.MatchPattern pattern, Gum.Memory.ScanMatchFunc func);

		public delegate bool ScanMatchFunc (Address address, size_t size);
	}

	namespace Cloak {
		public void add_thread (Gum.ThreadId id);
		public void remove_thread (Gum.ThreadId id);
		public bool has_thread (Gum.ThreadId id);
		public void enumerate_threads (Gum.Cloak.FoundThreadFunc func);

		public void add_range (Gum.MemoryRange range);
		public void remove_range (Gum.MemoryRange range);
		public GLib.Array<Gum.MemoryRange>? clip_range (Gum.MemoryRange range);
		public void enumerate_ranges (Gum.Cloak.FoundRangeFunc func);

		public void add_file_descriptor (int fd);
		public void remove_file_descriptor (int fd);
		public bool has_file_descriptor (int fd);
		public void enumerate_file_descriptors (Gum.Cloak.FoundFDFunc func);

		public delegate bool FoundThreadFunc (Gum.ThreadId id);
		public delegate bool FoundRangeFunc (Gum.MemoryRange range);
		public delegate bool FoundFDFunc (int fd);
	}

	public struct CpuContext {
	}

	public struct IA32CpuContext {
		public uint32 eip;

		public uint32 edi;
		public uint32 esi;
		public uint32 ebp;
		public uint32 esp;
		public uint32 ebx;
		public uint32 edx;
		public uint32 ecx;
		public uint32 eax;
	}

	public struct X64CpuContext {
		public uint64 rip;

		public uint64 r15;
		public uint64 r14;
		public uint64 r13;
		public uint64 r12;
		public uint64 r11;
		public uint64 r10;
		public uint64 r9;
		public uint64 r8;

		public uint64 rdi;
		public uint64 rsi;
		public uint64 rbp;
		public uint64 rsp;
		public uint64 rbx;
		public uint64 rdx;
		public uint64 rcx;
		public uint64 rax;
	}

	public struct ArmCpuContext {
		public uint32 cpsr;
		public uint32 pc;
		public uint32 sp;

		public uint32 r8;
		public uint32 r9;
		public uint32 r10;
		public uint32 r11;
		public uint32 r12;

		public uint32 r[8];
		public uint32 lr;
	}

	public struct Arm64CpuContext {
		public uint64 pc;
		public uint64 sp;

		public uint64 x[29];
		public uint64 fp;
		public uint64 lr;
		public uint8 q[128];
	}

	public struct MipsCpuContext {
		public uint32 pc;

		public uint32 gp;
		public uint32 sp;
		public uint32 fp;
		public uint32 ra;

		public uint32 hi;
		public uint32 lo;

		public uint32 at;

		public uint32 v0;
		public uint32 v1;

		public uint32 a0;
		public uint32 a1;
		public uint32 a2;
		public uint32 a3;

		public uint32 t0;
		public uint32 t1;
		public uint32 t2;
		public uint32 t3;
		public uint32 t4;
		public uint32 t5;
		public uint32 t6;
		public uint32 t7;
		public uint32 t8;
		public uint32 t9;

		public uint32 s0;
		public uint32 s1;
		public uint32 s2;
		public uint32 s3;
		public uint32 s4;
		public uint32 s5;
		public uint32 s6;
		public uint32 s7;

		public uint32 k0;
		public uint32 k1;
	}

	public delegate bool FoundRangeFunc (Gum.RangeDetails details);

	public struct ThreadId : size_t {
	}

	[CCode (cprefix = "GUM_THREAD_")]
	public enum ThreadState {
		RUNNING = 1,
		STOPPED,
		WAITING,
		UNINTERRUPTIBLE,
		HALTED
	}

	public struct ThreadDetails {
		public Gum.ThreadId id;
		public Gum.ThreadState state;
		public CpuContext cpu_context;
	}

	public struct ModuleDetails {
		public string name;
		public Gum.MemoryRange? range;
		public string path;
	}

	[CCode (cprefix = "GUM_IMPORT_")]
	public enum ImportType {
		FUNCTION = 1,
		VARIABLE
	}

	public struct ImportDetails {
		public Gum.ImportType type;
		public string name;
		public string module;
		public Gum.Address address;
	}

	[CCode (cprefix = "GUM_EXPORT_")]
	public enum ExportType {
		FUNCTION = 1,
		VARIABLE
	}

	public struct ExportDetails {
		public Gum.ExportType type;
		public string name;
		public Gum.Address address;
	}

	[CCode (cprefix = "GUM_SYMBOL_")]
	public enum SymbolType {
		UNKNOWN,
		UNDEFINED,
		ABSOLUTE,
		SECTION,
		PREBOUND_UNDEFINED,
		INDIRECT
	}

	public struct SymbolDetails {
		public bool is_global;
		public Gum.SymbolType type;
		public Gum.SymbolSection? section;
		public string name;
		public Gum.Address address;
	}

	public struct SymbolSection {
		public string id;
		public Gum.PageProtection prot;
	}

	public struct RangeDetails {
		public Gum.MemoryRange? range;
		public Gum.PageProtection prot;
		public Gum.FileMapping? file;
	}

	public struct FileMapping {
		public string path;
		public uint64 offset;
	}

	public struct Address : uint64 {
		public static Gum.Address from_pointer (void * p) {
			return (Gum.Address) (uintptr) p;
		}
	}

	public struct MemoryRange {
		public MemoryRange (Address base_address, size_t size) {
			this.base_address = base_address;
			this.size = size;
		}

		public Address base_address;
		public size_t size;
	}

	[Compact]
	[CCode (free_function = "gum_match_pattern_free")]
	public class MatchPattern {
		public MatchPattern.from_string (string match_str);
	}

	[Flags]
	[CCode (cprefix = "GUM_PAGE_")]
	public enum PageProtection {
		NO_ACCESS = 0,
		READ      = (1 << 0),
		WRITE     = (1 << 1),
		EXECUTE   = (1 << 2)
	}

	public class Exceptor : GLib.Object {
		public static Exceptor obtain ();
	}

	public bool symbol_details_from_address (void * address, out Gum.DebugSymbolDetails details);
	public string symbol_name_from_address (void * address);

	public void * find_function (string name);
	public GLib.Array<void *> find_functions_named (string name);
	public GLib.Array<void *> find_functions_matching (string str);

	[CCode (has_copy_function = false, has_destroy_function = false)]
	public struct DebugSymbolDetails {
		public Gum.Address address;
		public unowned string module_name;
		public unowned string symbol_name;
		public unowned string file_name;
		public uint line_number;
	}

	[CCode (cheader_filename = "gum/gum-heap.h")]
	public class InstanceTracker : GLib.Object {
		public InstanceTracker ();

		public void begin (Gum.InstanceVTable? vtable = null);
		public void end ();

		public uint peek_total_count (string type_name);
		public GLib.List peek_instances ();
		public void walk_instances (Gum.WalkInstanceFunc func);
	}

	public delegate void WalkInstanceFunc (Gum.InstanceDetails id);

	public struct InstanceVTable {
		void * create_instance;
		void * free_instance;

		void * type_id_to_name;
	}

	public struct InstanceDetails {
		public void * address;
		public uint ref_count;
		public string type_name;
	}

	[CCode (cheader_filename = "gum/gum-heap.h")]
	public class BoundsChecker : GLib.Object {
		public BoundsChecker ();

		public uint pool_size { get; set; }
		public uint front_alignment { get; set; }

		public void attach ();
		public void detach ();
	}

	[CCode (cprefix = "GUM_ATTACH_")]
	public enum AttachReturn {
		OK		  =  0,
		WRONG_SIGNATURE	  = -1,
		ALREADY_ATTACHED  = -2
	}

	[CCode (cprefix = "GUM_REPLACE_")]
	public enum ReplaceReturn {
		OK		  =  0,
		WRONG_SIGNATURE	  = -1,
		ALREADY_REPLACED  = -2
	}

	[CCode (cprefix = "GUM_")]
	public enum EventType {
		NOTHING	= 0,
		CALL	= (1 << 0),
		RET	= (1 << 1),
		EXEC	= (1 << 2)
	}

	[Compact]
	public struct AnyEvent {
		public EventType type;
	}

	[Compact]
	public struct CallEvent {
		public EventType type;

		public void * location;
		public void * target;
		public int depth;
	}

	[Compact]
	public struct RetEvent {
		public EventType type;

		public void * location;
		public void * target;
		public int depth;
	}

	[Compact]
	public struct ExecEvent {
		public EventType type;

		public void * location;
	}
}
