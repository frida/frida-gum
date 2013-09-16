[CCode (cheader_filename = "gum/gum.h")]
namespace Gum {
	public void init ();
	public void init_with_features (Gum.FeatureFlags features);
	public void deinit ();

	[Flags]
	[CCode (cprefix = "GUM_FEATURE_")]
	public enum FeatureFlags {
		SYMBOL_LOOKUP,

		NONE,
		ALL,
		DEFAULT
	}

	[CCode (cprefix = "GUM_CALL_")]
	public enum CallingConvention {
		CAPI,
		SYSAPI
	}

	[Compact]
	public class Closure {
		public Closure (Gum.CallingConvention conv, Gum.ClosureTarget target, GLib.Variant args);

		public void invoke ();
	}

	[CCode (has_target = false)]
	public delegate void ClosureTarget ();

	public class Interceptor : GLib.Object {
		public static Interceptor obtain ();

		public Gum.AttachReturn attach_listener (void * function_address, Gum.InvocationListener listener, void * listener_function_data = null);
		public void detach_listener (Gum.InvocationListener listener);

		public void replace_function (void * function_address, void * replacement_function, void * replacement_function_data = null);
		public void revert_function (void * function_address);

		public static Gum.InvocationContext get_current_invocation ();

		public void ignore_current_thread ();
		public void unignore_current_thread ();

		public void ignore_other_threads ();
		public void unignore_other_threads ();
	}

	public interface InvocationListener : GLib.Object {
		public abstract void on_enter (Gum.InvocationContext context);
		public abstract void on_leave (Gum.InvocationContext context);
	}

	[Compact]
	public class InvocationContext {
		public void * function;
		public void * cpu_context;

		public void * backend;

		public void * get_nth_argument (uint n);
		public void replace_nth_argument (uint n, void * val);
		public void * get_return_value ();

		public uint get_thread_id ();

		public void * get_listener_thread_data (size_t required_size);
		public void * get_listener_function_data ();
		public void * get_listener_function_invocation_data (size_t required_size);

		public void * get_replacement_function_data ();
	}

	public class Script : GLib.Object {
		public delegate void MessageHandler (Gum.Script script, string message, uint8[] data);

		public static Script from_string (string source) throws GLib.IOError;

		public unowned Stalker get_stalker ();

		public void set_message_handler (owned Gum.Script.MessageHandler func);

		public void load ();
		public void unload ();

		public void post_message (string message);
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
		public Stalker ();

		public void exclude (Gum.MemoryRange range);

		public int get_trust_threshold ();
		public void set_trust_threshold (int trust_threshold);

		public void garbage_collect ();

		public void follow_me (Gum.EventSink sink);
		public void unfollow_me ();
		public bool is_following_me ();

		// TODO: complete binding
	}

	public interface EventSink : GLib.Object {
		public abstract Gum.EventType query_mask ();
		public abstract void process (void * opaque_event);
	}

	namespace Process {
		public void enumerate_modules (Gum.Process.FoundModuleFunc func);
		public void enumerate_ranges (Gum.PageProtection prot, Gum.FoundRangeFunc func);

		public delegate bool FoundModuleFunc (string name, Gum.MemoryRange range, string path);
	}

	namespace Module {
		public void enumerate_exports (string module_name, Gum.Module.FoundExportFunc func);
		public void enumerate_ranges (string module_name, Gum.PageProtection prot, Gum.FoundRangeFunc func);
		public void * find_base_address (string module_name);
		public void * find_export_by_name (string module_name, string symbol_name);

		public delegate bool FoundExportFunc (string name, Address address);
	}

	public delegate bool FoundRangeFunc (Gum.MemoryRange range, Gum.PageProtection prot);

	namespace Memory {
		public uint8[] read (Address address, size_t len);
		public bool write (Address address, uint8[] bytes);
		public void scan (Gum.MemoryRange range, Gum.MatchPattern pattern, Gum.Memory.ScanMatchFunc func);

		public delegate bool ScanMatchFunc (Address address, size_t size);
	}

	public struct Address : uint64 {
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

	[CCode (cheader_filename = "gum/gum-heap.h")]
	public class InstanceTracker : GLib.Object {
		public InstanceTracker ();

		public void begin (Gum.InstanceVTable? vtable = null);
		public void end ();

		public uint peek_total_count (string type_name);
		public Gum.List peek_instances ();
		public void walk_instances (Gum.WalkInstanceFunc func);
	}

	public delegate void WalkInstanceFunc (Gum.InstanceDetails id);

	public struct InstanceVTable
	{
		void * create_instance;
		void * free_instance;

		void * type_id_to_name;
	}

	public struct InstanceDetails
	{
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

	/* Copied from glib-2.0.vapi */
	[Compact]
	[CCode (dup_function = "gum_list_copy", free_function = "gum_list_free")]
	public class List<G> {
		public List ();

		[ReturnsModifiedPointer ()]
		public void append (owned G data);
		[ReturnsModifiedPointer ()]
		public void prepend (owned G data);
		[ReturnsModifiedPointer ()]
		public void insert (owned G data, int position);
		[ReturnsModifiedPointer ()]
		public void insert_before (List<G> sibling, owned G data);
		[ReturnsModifiedPointer ()]
		public void insert_sorted (owned G data, GLib.CompareFunc compare_func);
		[ReturnsModifiedPointer ()]
		public void remove (G data);
		[ReturnsModifiedPointer ()]
		public void remove_link (List<G> llink);
		[ReturnsModifiedPointer ()]
		public void delete_link (List<G> link_);
		[ReturnsModifiedPointer ()]
		public void remove_all (G data);

		public uint length ();
		public List<unowned G> copy ();
		[ReturnsModifiedPointer ()]
		public void reverse ();
		[ReturnsModifiedPointer ()]
		public void sort (GLib.CompareFunc compare_func);
		[ReturnsModifiedPointer ()]
		public void insert_sorted_with_data (owned G data, GLib.CompareDataFunc compare_func);
		[ReturnsModifiedPointer ()]
		public void sort_with_data (GLib.CompareDataFunc compare_func);
		[ReturnsModifiedPointer ()]
		public void concat (owned List<G> list2);
		public void @foreach (GLib.Func func);

		public unowned List<G> first ();
		public unowned List<G> last ();
		public unowned List<G> nth (uint n);
		public unowned G nth_data (uint n);
		public unowned List<G> nth_prev (uint n);

		public unowned List<G> find (G data);
		public unowned List<G> find_custom (G data, GLib.CompareFunc func);
		public int position (List<G> llink);
		public int index (G data);

		public G data;
		public List<G> next;
		public unowned List<G> prev;
	}

	[CCode (cprefix = "GUM_ATTACH_")]
	public enum AttachReturn {
		OK		  =  0,
		WRONG_SIGNATURE	  = -1,
		ALREADY_ATTACHED  = -2
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
