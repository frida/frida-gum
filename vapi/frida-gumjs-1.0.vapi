namespace Gum {
	[CCode (cheader_filename = "gumjs/gumscript.h")]
	public class Script : GLib.Object {
		[CCode (cprefix = "GUM_SCRIPT_FLAVOR_")]
		public enum Flavor {
			KERNEL,
			USER
		}
		public delegate void MessageHandler (Gum.Script script, string message, uint8[] data);
		public delegate void DebugMessageHandler (string message);

		public static async Script from_string (string name, string source, Flavor flavor, GLib.Cancellable? cancellable = null) throws GLib.IOError;
		public static Script from_string_sync (string name, string source, Flavor flavor, GLib.Cancellable? cancellable = null) throws GLib.IOError;

		public unowned Stalker get_stalker ();

		public void set_message_handler (owned Gum.Script.MessageHandler handler);

		public async void load (GLib.Cancellable? cancellable = null);
		public void load_sync (GLib.Cancellable? cancellable = null);
		public async void unload (GLib.Cancellable? cancellable = null);
		public void unload_sync (GLib.Cancellable? cancellable = null);

		public void post_message (string message);

		public static void set_debug_message_handler (owned Gum.Script.DebugMessageHandler? handler);
		public static void post_debug_message (string message);

		public static void ignore (Gum.ThreadId thread_id);
		public static void unignore (Gum.ThreadId thread_id);
		public static void is_ignoring (Gum.ThreadId thread_id);
	}
}
