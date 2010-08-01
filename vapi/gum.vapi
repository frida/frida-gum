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
