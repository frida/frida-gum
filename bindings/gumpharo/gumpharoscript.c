#include "gumpharoscript.h"

#include "gumpharo.h"

#include <json-glib/json-glib.h>

struct _GumPharoScript
{
  GObject parent;

  guint id;
  gchar * name;
  gchar * source;

  GumPharoScriptMessageHandler handler;
  gpointer handler_data;
  GDestroyNotify handler_data_destroy;
};

G_DEFINE_TYPE (GumPharoScript, gum_pharo_script, G_TYPE_OBJECT)

static gchar * gum_pharo_stringify (JsonBuilder * builder);
static void gum_pharo_script_finalize (GObject * object);
static void gum_pharo_script_control (GumPharoScript * self,
    const gchar * kind);
static void gum_pharo_deliver_envelope (const gchar * envelope, GBytes * data,
    gpointer user_data);

static GHashTable * gum_pharo_scripts;
static guint gum_pharo_next_id = 1;
static GRWLock gum_pharo_scripts_lock;

GumPharoScript *
gum_pharo_script_new (const gchar * name,
                      const gchar * source)
{
  GumPharoScript * script;

  gum_pharo_runtime_ensure_started ();

  script = g_object_new (GUM_TYPE_PHARO_SCRIPT, NULL);
  script->name = g_strdup (name);
  script->source = g_strdup (source);

  g_rw_lock_writer_lock (&gum_pharo_scripts_lock);

  if (gum_pharo_scripts == NULL)
  {
    gum_pharo_scripts = g_hash_table_new (NULL, NULL);
    gum_pharo_set_message_handler (gum_pharo_deliver_envelope, NULL);
  }
  script->id = gum_pharo_next_id++;
  g_hash_table_insert (gum_pharo_scripts, GUINT_TO_POINTER (script->id),
      script);

  g_rw_lock_writer_unlock (&gum_pharo_scripts_lock);

  gum_pharo_script_control (script, "gum:create");

  return script;
}

void
gum_pharo_script_load (GumPharoScript * self)
{
  gum_pharo_script_control (self, "gum:load");
}

void
gum_pharo_script_unload (GumPharoScript * self)
{
  gum_pharo_script_control (self, "gum:unload");
}

void
gum_pharo_script_post (GumPharoScript * self,
                       const gchar * message,
                       GBytes * data)
{
  JsonBuilder * builder;
  gchar * envelope;

  builder = json_builder_new ();
  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "id");
  json_builder_add_int_value (builder, self->id);
  json_builder_set_member_name (builder, "payload");
  json_builder_add_string_value (builder, message);
  json_builder_end_object (builder);

  envelope = gum_pharo_stringify (builder);
  gum_pharo_post (envelope, data);

  g_free (envelope);
  g_object_unref (builder);
}

void
gum_pharo_script_set_message_handler (GumPharoScript * self,
                                      GumPharoScriptMessageHandler handler,
                                      gpointer data,
                                      GDestroyNotify data_destroy)
{
  if (self->handler_data_destroy != NULL)
    self->handler_data_destroy (self->handler_data);

  self->handler = handler;
  self->handler_data = data;
  self->handler_data_destroy = data_destroy;
}

static void
gum_pharo_script_control (GumPharoScript * self,
                          const gchar * kind)
{
  JsonBuilder * builder;
  gchar * message;

  builder = json_builder_new ();
  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "type");
  json_builder_add_string_value (builder, kind);
  json_builder_set_member_name (builder, "id");
  json_builder_add_int_value (builder, self->id);
  json_builder_set_member_name (builder, "name");
  json_builder_add_string_value (builder, self->name);
  json_builder_set_member_name (builder, "source");
  json_builder_add_string_value (builder, self->source);
  json_builder_end_object (builder);

  message = gum_pharo_stringify (builder);
  gum_pharo_post (message, NULL);

  g_free (message);
  g_object_unref (builder);
}

static void
gum_pharo_deliver_envelope (const gchar * envelope,
                            GBytes * data,
                            gpointer user_data)
{
  JsonParser * parser;
  JsonObject * root;
  GumPharoScript * script;
  JsonNode * payload;
  gchar * message;

  parser = json_parser_new ();
  if (!json_parser_load_from_data (parser, envelope, -1, NULL))
    goto beach;
  root = json_node_get_object (json_parser_get_root (parser));

  g_rw_lock_reader_lock (&gum_pharo_scripts_lock);
  script = g_hash_table_lookup (gum_pharo_scripts,
      GUINT_TO_POINTER (json_object_get_int_member (root, "id")));
  g_rw_lock_reader_unlock (&gum_pharo_scripts_lock);

  if (script == NULL || script->handler == NULL)
    goto beach;

  payload = json_object_get_member (root, "payload");
  message = json_to_string (payload, FALSE);

  script->handler (script, message, data, script->handler_data);

  g_free (message);

beach:
  g_object_unref (parser);
}

static gchar *
gum_pharo_stringify (JsonBuilder * builder)
{
  JsonNode * root;
  gchar * text;

  root = json_builder_get_root (builder);
  text = json_to_string (root, FALSE);
  json_node_unref (root);

  return text;
}

static void
gum_pharo_script_class_init (GumPharoScriptClass * klass)
{
  G_OBJECT_CLASS (klass)->finalize = gum_pharo_script_finalize;
}

static void
gum_pharo_script_init (GumPharoScript * self)
{
}

static void
gum_pharo_script_finalize (GObject * object)
{
  GumPharoScript * self = GUM_PHARO_SCRIPT (object);

  g_rw_lock_writer_lock (&gum_pharo_scripts_lock);
  g_hash_table_remove (gum_pharo_scripts, GUINT_TO_POINTER (self->id));
  g_rw_lock_writer_unlock (&gum_pharo_scripts_lock);

  if (self->handler_data_destroy != NULL)
    self->handler_data_destroy (self->handler_data);
  g_free (self->source);
  g_free (self->name);

  G_OBJECT_CLASS (gum_pharo_script_parent_class)->finalize (object);
}
