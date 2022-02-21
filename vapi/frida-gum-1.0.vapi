[CCode (cheader_filename = "gum/gum.h", gir_namespace = "FridaGum", gir_version = "1.0")]
namespace Gum {
	public void init ();
	public void shutdown ();
	public void deinit ();

	public void init_embedded ();
	public void deinit_embedded ();

	public void prepare_to_fork ();
	public void recover_from_fork_in_parent ();
	public void recover_from_fork_in_child ();

	public void * sign_code_pointer (void * value);
	public void * strip_code_pointer (void * value);
	public Gum.Address sign_code_address (Gum.Address value);
	public Gum.Address strip_code_address (Gum.Address value);
	public Gum.PtrauthSupport query_ptrauth_support ();

	public uint query_page_size ();
	public bool query_is_rwx_supported ();
	public Gum.RwxSupport query_rwx_support ();

	public void ensure_code_readable (void * address, size_t size);

	public void mprotect (void * address, size_t size, Gum.PageProtection prot);
	public bool try_mprotect (void * address, size_t size, Gum.PageProtection prot);

	public void clear_cache (void * address, size_t size);

	public uint peek_private_memory_usage ();

	public void * malloc (size_t size);
	public void * malloc0 (size_t size);
	public void * calloc (size_t count, size_t size);
	public void * realloc (void * mem, size_t size);
	public void * memalign (size_t alignment, size_t size);
	public void * memdup (void * mem, size_t byte_size);
	public void free (void * mem);

	public void * alloc_n_pages (uint n_pages, Gum.PageProtection prot);
	public void * try_alloc_n_pages (uint n_pages, Gum.PageProtection prot);
	public void * alloc_n_pages_near (uint n_pages, Gum.PageProtection prot, Gum.AddressSpec spec);
	public void * try_alloc_n_pages_near (uint n_pages, Gum.PageProtection prot, Gum.AddressSpec spec);
	public void query_page_allocation_range (void * mem, uint size, out Gum.MemoryRange range);
	public void free_pages (void * mem);

	public errordomain Error {
		FAILED,
		NOT_FOUND,
		EXISTS,
		INVALID_ARGUMENT,
		NOT_SUPPORTED,
		INVALID_DATA,
	}

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
		INVALID,
		IA32,
		AMD64,
		ARM,
		ARM64,
		MIPS,
	}

	[CCode (cprefix = "GUM_PTRAUTH_")]
	public enum PtrauthSupport {
		INVALID,
		UNSUPPORTED,
		SUPPORTED
	}

	[CCode (cprefix = "GUM_RWX_")]
	public enum RwxSupport {
		NONE,
		ALLOCATIONS_ONLY,
		FULL
	}

	public class Interceptor : GLib.Object {
		public static Interceptor obtain ();

		public Gum.AttachReturn attach (void * function_address, Gum.InvocationListener listener, void * listener_function_data = null);
		public void detach (Gum.InvocationListener listener);

		public Gum.ReplaceReturn replace (void * function_address, void * replacement_function, void * replacement_data = null);
		public void revert (void * function_address);

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
		public void * get_listener_invocation_data (size_t required_size);

		public void * get_replacement_data ();
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

		public void activate (void * target);
		public void deactivate ();

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
		public unowned string query_libc_name ();
		public bool is_debugger_attached ();
		public Gum.ThreadId get_current_thread_id ();
		public bool has_thread (Gum.ThreadId thread_id);
		public bool modify_thread (Gum.ThreadId thread_id, Gum.ModifyThreadFunc func);
		public void enumerate_threads (Gum.FoundThreadFunc func);
		public void enumerate_modules (Gum.FoundModuleFunc func);
		public void enumerate_ranges (Gum.PageProtection prot, Gum.FoundRangeFunc func);
	}

	namespace Thread {
		public uint try_get_ranges (Gum.MemoryRange[] ranges);
	}

	namespace Module {
		public bool ensure_initialized (string module_name);
		public void enumerate_imports (string module_name, Gum.FoundImportFunc func);
		public void enumerate_exports (string module_name, Gum.FoundExportFunc func);
		public void enumerate_symbols (string module_name, Gum.FoundSymbolFunc func);
		public void enumerate_ranges (string module_name, Gum.PageProtection prot, Gum.FoundRangeFunc func);
		public void * find_base_address (string module_name);
		public void * find_export_by_name (string? module_name, string symbol_name);
	}

	namespace Memory {
		public bool is_readable (void * address, size_t len);
		public uint8[] read (Address address, size_t len);
		public bool write (Address address, uint8[] bytes);
		public bool patch_code (void * address, size_t size, Gum.Memory.PatchApplyFunc apply);
		public bool mark_code (void * address, size_t size);

		public void scan (Gum.MemoryRange range, Gum.MatchPattern pattern, Gum.Memory.ScanMatchFunc func);

		public void * allocate (void * address, size_t size, size_t alignment, Gum.PageProtection prot);
		public bool free (void * address, size_t size);
		public bool release (void * address, size_t size);
		public bool commit (void * address, size_t size, Gum.PageProtection prot);
		public bool decommit (void * address, size_t size);

		public delegate void PatchApplyFunc (void * mem);
		public delegate bool ScanMatchFunc (Address address, size_t size);
	}

	namespace InternalHeap {
		public void ref ();
		public void unref ();
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

	public delegate void ModifyThreadFunc (Gum.ThreadId thread_id, CpuContext * cpu_context);
	public delegate bool FoundThreadFunc (Gum.ThreadDetails details);
	public delegate bool FoundModuleFunc (Gum.ModuleDetails details);
	public delegate bool FoundRangeFunc (Gum.RangeDetails details);
	public delegate bool FoundImportFunc (Gum.ImportDetails details);
	public delegate bool FoundExportFunc (Gum.ExportDetails details);
	public delegate bool FoundSymbolFunc (Gum.SymbolDetails details);

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
		public Gum.PageProtection protection;
	}

	public struct RangeDetails {
		public Gum.MemoryRange? range;
		public Gum.PageProtection protection;
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

	public struct AddressSpec {
		public AddressSpec (void * near_address, size_t max_distance) {
			this.near_address = near_address;
			this.max_distance = max_distance;
		}

		public void * near_address;
		public size_t max_distance;
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
	[CCode (free_function = "gum_match_pattern_unref")]
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
		public static void disable ();
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

	public class DarwinModule : GLib.Object {
		public Filetype filetype;
		public string? name;
		public string? uuid;

		public DarwinPort task;
		public bool is_local;
		public bool is_kernel;
		public Gum.CpuType cpu_type;
		public size_t pointer_size;
		public size_t page_size;
		public Gum.Address base_address;
		public string? source_path;
		public GLib.Bytes? source_blob;

		public DarwinModuleImage image;

		public void * info;
		public void * symtab;
		public void * dysymtab;

		public Gum.Address preferred_address;

		public GLib.Array<DarwinSegment> segments;

		public bool lacks_exports_for_reexports {
			get;
		}

		public Gum.Address slide {
			get;
		}

		public enum Filetype {
			OBJECT = 1,
			EXECUTE,
			FVMLIB,
			CORE,
			PRELOAD,
			DYLIB,
			DYLINKER,
			BUNDLE,
			DYLIB_STUB,
			DSYM,
			KEXT_BUNDLE,
			FILESET,
		}

		[Flags]
		public enum Flags {
			NONE        = 0,
			HEADER_ONLY = (1 << 0),
		}

		public DarwinModule.from_file (string path, Gum.CpuType cpu_type, Gum.PtrauthSupport ptrauth_support, Gum.DarwinModule.Flags flags = NONE) throws GLib.Error;
		public DarwinModule.from_blob (GLib.Bytes blob, Gum.CpuType cpu_type, Gum.PtrauthSupport ptrauth_support, Gum.DarwinModule.Flags flags = NONE) throws GLib.Error;
		public DarwinModule.from_memory (string? name, Gum.DarwinPort task, Gum.Address base_address, Gum.DarwinModule.Flags flags = NONE) throws GLib.Error;

		public bool load () throws Gum.Error;

		public bool resolve_export (string symbol, out Gum.DarwinExportDetails details);
		public Gum.Address resolve_symbol_address (string symbol);
		public void enumerate_imports (Gum.FoundImportFunc func);
		public void enumerate_exports (Gum.FoundDarwinExportFunc func);
		public void enumerate_symbols (Gum.FoundDarwinSymbolFunc func);
		public void enumerate_sections (Gum.FoundDarwinSectionFunc func);
		public bool is_address_in_text_section (Gum.Address address);
		public void enumerate_chained_fixups (Gum.FoundDarwinChainedFixupsFunc func);
		public void enumerate_rebases (Gum.FoundDarwinRebaseFunc func);
		public void enumerate_binds (Gum.FoundDarwinBindFunc func);
		public void enumerate_lazy_binds (Gum.FoundDarwinBindFunc func);
		public void enumerate_init_pointers (Gum.FoundDarwinInitPointersFunc func);
		public void enumerate_init_offsets (Gum.FoundDarwinInitOffsetsFunc func);
		public void enumerate_term_pointers (Gum.FoundDarwinTermPointersFunc func);
		public void enumerate_dependencies (Gum.FoundDarwinDependencyFunc func);
		public unowned string? get_dependency_by_ordinal (int ordinal);
	}

	public delegate bool FoundDarwinExportFunc (Gum.DarwinExportDetails details);
	public delegate bool FoundDarwinSymbolFunc (Gum.DarwinSymbolDetails details);
	public delegate bool FoundDarwinSectionFunc (Gum.DarwinSectionDetails details);
	public delegate bool FoundDarwinChainedFixupsFunc (Gum.DarwinChainedFixupsDetails details);
	public delegate bool FoundDarwinRebaseFunc (Gum.DarwinRebaseDetails details);
	public delegate bool FoundDarwinBindFunc (Gum.DarwinBindDetails details);
	public delegate bool FoundDarwinInitPointersFunc (Gum.DarwinInitPointersDetails details);
	public delegate bool FoundDarwinInitOffsetsFunc (Gum.DarwinInitOffsetsDetails details);
	public delegate bool FoundDarwinTermPointersFunc (Gum.DarwinTermPointersDetails details);
	public delegate bool FoundDarwinDependencyFunc (string path);

	[Compact]
	public class DarwinModuleImage {
		public void * data;
		public uint64 size;
		public void * linkedit;

		public uint64 source_offset;
		public uint64 source_size;
		public uint64 shared_offset;
		public uint64 shared_size;
		public GLib.Array<Gum.DarwinModuleImageSegment> shared_segments;

		public GLib.Bytes bytes;
		public void * malloc_data;
	}

	public struct DarwinModuleImageSegment {
		public uint64 offset;
		public uint64 size;
		public int protection;
	}

	public struct DarwinSectionDetails {
		public string segment_name;
		public string section_name;
		public Gum.Address vm_address;
		public uint64 size;
		public Gum.DarwinPageProtection protection;
		public uint32 file_offset;
		public uint32 flags;
	}

	public struct DarwinChainedFixupsDetails {
		public Gum.Address vm_address;
		uint64 file_offset;
		uint32 size;
	}

	public struct DarwinRebaseDetails {
		public Gum.DarwinSegment? segment;
		public uint64 offset;
		public DarwinRebaseType type;
		public Gum.Address slide;
	}

	public struct DarwinBindDetails {
		public Gum.DarwinSegment? segment;
		public uint64 offset;
		public Gum.DarwinBindType type;
		public Gum.DarwinBindOrdinal library_ordinal;
		public string symbol_name;
		public Gum.DarwinBindSymbolFlags symbol_flags;
		public int64 addend;
	}

	public struct DarwinThreadedItem {
		public bool is_authenticated;
		public Gum.DarwinThreadedItemType type;
		public uint16 delta;
		public uint8 key;
		public bool has_address_diversity;
		public uint16 diversity;

		public uint16 bind_ordinal;

		public Gum.Address rebase_address;

		public static void parse (uint64 value, out Gum.DarwinThreadedItem result);
	}

	public struct DarwinInitPointersDetails {
		public Gum.Address address;
		public uint64 count;
	}

	public struct DarwinInitOffsetsDetails {
		public Gum.Address address;
		public uint64 count;
	}

	public struct DarwinTermPointersDetails {
		public Gum.Address address;
		public uint64 count;
	}

	public struct DarwinSegment {
		public string name;
		public Gum.Address vm_address;
		public uint64 vm_size;
		public uint64 file_offset;
		public uint64 file_size;
		public Gum.DarwinPageProtection protection;
	}

	public struct DarwinExportDetails {
		public string name;
		public uint64 flags;

		public uint64 offset;

		public uint64 stub;
		public uint64 resolver;

		public int reexport_library_ordinal;
		public string reexport_symbol;
	}

	public struct DarwinSymbolDetails {
		public string name;
		public Gum.Address address;

		public uint8 type;
		public uint8 section;
		public uint16 description;
	}

	[CCode (cprefix = "GUM_DARWIN_REBASE_")]
	public enum DarwinRebaseType {
		POINTER = 1,
		TEXT_ABSOLUTE32,
		TEXT_PCREL32,
	}

	[CCode (cprefix = "GUM_DARWIN_BIND_")]
	public enum DarwinBindType {
		POINTER = 1,
		TEXT_ABSOLUTE32,
		TEXT_PCREL32,
		THREADED_TABLE,
		THREADED_ITEMS,
	}

	[CCode (cprefix = "GUM_DARWIN_THREADED_")]
	public enum DarwinThreadedItemType {
		REBASE,
		BIND
	}

	[CCode (cprefix = "GUM_DARWIN_BIND_")]
	public enum DarwinBindOrdinal {
		SELF            =  0,
		MAIN_EXECUTABLE = -1,
		FLAT_LOOKUP     = -2,
		WEAK_LOOKUP     = -3,
	}

	[Flags]
	[CCode (cprefix = "GUM_DARWIN_BIND_")]
	public enum DarwinBindSymbolFlags {
		WEAK_IMPORT         = 0x1,
		NON_WEAK_DEFINITION = 0x8,
	}

	public const int DARWIN_EXPORT_KIND_MASK;

	[CCode (cprefix = "GUM_DARWIN_EXPORT_")]
	public enum DarwinExportSymbolKind {
		REGULAR,
		THREAD_LOCAL,
		ABSOLUTE
	}

	[Flags]
	[CCode (cprefix = "GUM_DARWIN_EXPORT_")]
	public enum DarwinExportSymbolFlags {
		WEAK_DEFINITION   = 0x04,
		REEXPORT          = 0x08,
		STUB_AND_RESOLVER = 0x10,
	}

	[CCode (has_type_id = false)]
	public struct DarwinPort : uint {
		[CCode (cname = "GUM_DARWIN_PORT_NULL")]
		public const DarwinPort NULL;
	}

	[CCode (has_type_id = false)]
	public struct DarwinPageProtection : int {
	}
}
