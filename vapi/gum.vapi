[CCode (cheader_filename = "gum/gum.h")]
namespace Gum {
	public void init ();

	public class Interceptor : GLib.Object {
		public static Interceptor obtain ();

		public Gum.AttachReturn attach_listener (void * function_address, Gum.InvocationListener listener, void * function_instance_data);
		public void detach_listener (Gum.InvocationListener listener);

		/* TODO: bind the rest if needed */
	}

	public interface InvocationListener : GLib.Object {
		public abstract void on_enter (Gum.InvocationContext ctx);
		public abstract void on_leave (Gum.InvocationContext ctx);
		public void * provide_thread_data (void * function_instance_data, uint thread_id);
	}

	[Compact]
	public class InvocationContext {
		public InvocationContext parent;

		public void * instance_data;
		public void * thread_data;

		public void * cpu_context;

		private void * backend;

		public void * get_nth_argument (uint n);
		public void replace_nth_argument (uint n, void * val);
		public void * get_return_value ();
	}

	public class Script : GLib.Object {
		public delegate void MessageHandler (Gum.Script script, owned GLib.Variant msg);

		public static Script from_string (string script_text) throws GLib.IOError;

		public void set_message_handler (owned Gum.Script.MessageHandler func);

		public void execute (Gum.InvocationContext ctx);

		public void * get_code_address ();
		public uint get_code_size ();
	}

	public class Stalker : GLib.Object {
		public Stalker ();

		public void follow_me (Gum.EventSink sink);
		public void unfollow_me ();
	}

	public interface EventSink : GLib.Object {
		public abstract Gum.EventType query_mask ();
		public abstract void process (void * opaque_event);
	}

	[CCode (cheader_filename = "gum/gum-heap.h")]
	public class InstanceTracker : GLib.Object {
		public InstanceTracker ();

		public uint peek_total_count (string type_name);
		public Gum.List peek_stale ();
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
		OK               =  0,
		WRONG_SIGNATURE  = -1,
		ALREADY_ATTACHED = -2
	}

	[CCode (cprefix = "GUM_")]
	public enum EventType {
		NOTHING = 0,
		CALL    = 1 << 0,
		RET     = 1 << 1,
		EXEC    = 1 << 2,
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
