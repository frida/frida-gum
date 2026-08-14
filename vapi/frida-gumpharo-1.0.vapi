namespace Gum {
	[CCode (cheader_filename = "gumpharo/gumpharoscript.h", type_cname = "GumPharoScriptClass")]
	public class PharoScript : GLib.Object {
		public delegate void MessageHandler (PharoScript script, string message, GLib.Bytes? data);

		public PharoScript (string name, string source);

		public void load ();
		public void unload ();
		public void post (string message, GLib.Bytes? data = null);

		public void set_message_handler (owned MessageHandler handler);
	}
}
