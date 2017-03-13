namespace Gum {
	[CCode (cheader_filename = "gumjs/gumscriptbackend.h")]
	public interface ScriptBackend : GLib.Object {
		public delegate void DebugMessageHandler (string message);

		public static unowned ScriptBackend obtain ();
		public static unowned ScriptBackend obtain_v8 ();
		public static unowned ScriptBackend obtain_duk ();

		public async Script create (string name, string source, GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public Script create_sync (string name, string source, GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public async Script create_from_bytes (string name, GLib.Bytes bytes, GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public Script create_from_bytes_sync (string name, GLib.Bytes bytes, GLib.Cancellable? cancellable = null) throws GLib.IOError;

		public async GLib.Bytes compile (string source, GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public GLib.Bytes compile_sync (string source, GLib.Cancellable? cancellable = null) throws GLib.IOError;

		public void set_debug_message_handler (owned Gum.ScriptBackend.DebugMessageHandler? handler);
		public void post_debug_message (string message);
	}

	[CCode (cheader_filename = "gumjs/gumscript.h")]
	public interface Script : GLib.Object {
		public delegate void MessageHandler (Gum.Script script, string message, GLib.Bytes? data);

		public async void load (GLib.Cancellable? cancellable = null);
		public void load_sync (GLib.Cancellable? cancellable = null);
		public async void unload (GLib.Cancellable? cancellable = null);
		public void unload_sync (GLib.Cancellable? cancellable = null);

		public void set_message_handler (owned Gum.Script.MessageHandler handler);
		public void post (string message, GLib.Bytes? data = null);

		public unowned Stalker get_stalker ();
	}
}
