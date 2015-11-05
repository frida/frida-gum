namespace Gum {
	[CCode (cheader_filename = "gumjs/gumscriptbackend.h")]
	public interface ScriptBackend : GLib.Object {
		public static unowned ScriptBackend obtain ();

		public async Script create (string name, string source, GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public Script create_sync (string name, string source, GLib.Cancellable? cancellable = null) throws GLib.IOError;

		public void set_debug_message_handler (owned Gum.Script.DebugMessageHandler? handler);
		public void post_debug_message (string message);

		public void ignore (Gum.ThreadId thread_id);
		public void unignore (Gum.ThreadId thread_id);
		public void unignore_later (Gum.ThreadId thread_id);
		public void is_ignoring (Gum.ThreadId thread_id);

		public bool supports_unload ();
	}

	[CCode (cheader_filename = "gumjs/gumscript.h")]
	public interface Script : GLib.Object {
		public delegate void MessageHandler (Gum.Script script, string message, GLib.Bytes? data);
		public delegate void DebugMessageHandler (string message);

		public async void load (GLib.Cancellable? cancellable = null);
		public void load_sync (GLib.Cancellable? cancellable = null);
		public async void unload (GLib.Cancellable? cancellable = null);
		public void unload_sync (GLib.Cancellable? cancellable = null);

		public void set_message_handler (owned Gum.Script.MessageHandler handler);
		public void post_message (string message);

		public unowned Stalker get_stalker ();
	}
}
