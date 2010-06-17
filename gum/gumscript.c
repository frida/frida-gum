/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumscript.h"

#include "gumcodewriter.h"
#include "gummemory.h"

#include <string.h>
#include <gio/gio.h> /* FIXME: piggy-backing on IOError for now */

typedef enum _GumVariableType GumVariableType;
typedef struct _GumVariable GumVariable;

typedef void (* GumScriptEntrypoint) (GumCpuContext * cpu_context,
    void * stack_arguments);

struct _GumScriptPrivate
{
  GHashTable * variable_by_name;

  GumScriptEntrypoint entrypoint;

  guint8 * code;
  GumCodeWriter code_writer;
};

enum _GumVariableType
{
  GUM_VARIABLE_ANSI_STRING,
  GUM_VARIABLE_WIDE_STRING
};

struct _GumVariable
{
  GumVariableType type;

  struct
  {
    gchar * ansi_string;
    gunichar2 * wide_string;
    guint string_length;
  } value;
};

#define GUM_SCRIPT_ESP_OFFSET_TO_CPU_CONTEXT 4
#define GUM_SCRIPT_ESP_OFFSET_TO_STACK_ARGS  8

static void gum_script_finalize (GObject * object);

static gboolean gum_script_handle_variable_declaration (GumScript * self,
    GScanner * scanner);
static gboolean gum_script_handle_replace_argument (GumScript * self,
    GScanner * scanner);

static GumVariable * gum_script_add_wide_string_variable (GumScript * self,
    const gchar * name, const gchar * value_utf8);
static GumVariable * gum_script_add_variable (GumScript * self,
    const gchar * name, GumVariableType type);
static gboolean gum_script_has_variable_named (GumScript * self,
    const gchar * name);
static GumVariable * gum_script_find_variable_named (GumScript * self,
    const gchar * name);

static GumVariable * gum_variable_new (GumVariableType type);
static void gum_variable_free (GumVariable * var);

static void gum_script_handle_parse_error (GScanner * scanner, gchar * message,
    gboolean error);
static void gum_script_init_scanner_config (GScannerConfig * scanner_config);

G_DEFINE_TYPE (GumScript, gum_script, G_TYPE_OBJECT);

static void
gum_script_class_init (GumScriptClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumScriptPrivate));

  object_class->finalize = gum_script_finalize;
}

static void
gum_script_init (GumScript * self)
{
  GumScriptPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_SCRIPT, GumScriptPrivate);

  priv->variable_by_name = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) gum_variable_free);

  priv->code = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RWX);
  gum_code_writer_init (&priv->code_writer, priv->code);
}

static void
gum_script_finalize (GObject * object)
{
  GumScript * self = GUM_SCRIPT (object);
  GumScriptPrivate * priv = self->priv;

  gum_code_writer_free (&priv->code_writer);
  gum_free_pages (priv->code);

  g_hash_table_unref (priv->variable_by_name);

  G_OBJECT_CLASS (gum_script_parent_class)->finalize (object);
}

GumScript *
gum_script_from_string (const gchar * script_text,
                        GError ** error)
{
  GumScript * script;
  GumScriptPrivate * priv;
  GScannerConfig scanner_config = { 0, };
  GScanner * scanner;
  GString * parse_messages;

  script = GUM_SCRIPT (g_object_new (GUM_TYPE_SCRIPT, NULL));
  priv = script->priv;

  gum_script_init_scanner_config (&scanner_config);

  scanner = g_scanner_new (&scanner_config);

  parse_messages = g_string_new ("");
  scanner->msg_handler = gum_script_handle_parse_error;
  scanner->user_data = parse_messages;

  g_scanner_input_text (scanner, script_text, (guint) strlen (script_text));

  while (!g_scanner_eof (scanner))
  {
    GTokenType token_type;
    const gchar * statement_type;
    gboolean statement_is_valid;

    token_type = g_scanner_get_next_token (scanner);
    if (token_type == G_TOKEN_EOF)
      break;

    if (token_type != G_TOKEN_IDENTIFIER)
    {
      g_scanner_unexp_token (scanner, G_TOKEN_IDENTIFIER, NULL, NULL, NULL,
          "expected statement", TRUE);
      goto parse_error;
    }

    statement_type = scanner->value.v_string;

    if (strcmp (statement_type, "var") == 0)
    {
      statement_is_valid = gum_script_handle_variable_declaration (script, scanner);
    }
    else if (strcmp (statement_type, "ReplaceArgument") == 0)
    {
      statement_is_valid = gum_script_handle_replace_argument (script, scanner);
    }
    else
    {
      g_scanner_error (scanner, "unexpected identifier: '%s'", statement_type);
      statement_is_valid = FALSE;
    }

    if (!statement_is_valid)
      goto parse_error;
  }

  if (gum_code_writer_offset (&priv->code_writer) == 0)
  {
    g_scanner_error (scanner, "script without any statements");
    goto parse_error;
  }

  gum_code_writer_put_ret (&priv->code_writer);

  priv->entrypoint = (GumScriptEntrypoint) priv->code;

  g_scanner_destroy (scanner);
  g_string_free (parse_messages, TRUE);

  return script;

  /* ERRORS */
parse_error:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Parse error: %s", parse_messages->str);

    g_scanner_destroy (scanner);
    g_string_free (parse_messages, TRUE);
    g_object_unref (script);

    return NULL;
  }
}

void
gum_script_execute (GumScript * self,
                    GumCpuContext * cpu_context,
                    void * stack_arguments)
{
  self->priv->entrypoint (cpu_context, stack_arguments);
}

gpointer
gum_script_get_code_address (GumScript * self)
{
  return self->priv->code;
}

guint
gum_script_get_code_size (GumScript * self)
{
  return gum_code_writer_offset (&self->priv->code_writer);
}

static gboolean
gum_script_handle_variable_declaration (GumScript * self,
                                        GScanner * scanner)
{
  gchar * variable_name = NULL;
 
  if (g_scanner_get_next_token (scanner) != G_TOKEN_IDENTIFIER)
  {
    g_scanner_unexp_token (scanner, G_TOKEN_IDENTIFIER, NULL, NULL, NULL,
        "expected variable name", TRUE);
    goto error;
  }

  if (gum_script_has_variable_named (self, scanner->value.v_string))
  {
    g_scanner_error (scanner, "variable %s has already been defined",
        scanner->value.v_string);
    goto error;
  }

  variable_name = g_strdup (scanner->value.v_string);

  if (g_scanner_get_next_token (scanner) != G_TOKEN_EQUAL_SIGN)
  {
    g_scanner_unexp_token (scanner, G_TOKEN_EQUAL_SIGN, NULL, NULL, NULL,
        "expected equal sign to follow variable name", TRUE);
    goto error;
  }

  switch (g_scanner_get_next_token (scanner))
  {
    case G_TOKEN_STRING:
    {
      const char * string_end_quote;

      string_end_quote = scanner->text - 1;
      switch (*string_end_quote)
      {
        case '"':
          gum_script_add_wide_string_variable (self, variable_name,
              scanner->value.v_string);
          break;

        case '\'':
          g_scanner_error (scanner,
              "only unicode strings are supported for now");
          goto error;

        default:
          g_assert_not_reached ();
      }

      break;
    }

    default:
      g_scanner_error (scanner, "only strings are supported for now");
      goto error;
  }

  g_free (variable_name);
  return TRUE;

error:
  g_free (variable_name);
  return FALSE;
}

static gboolean
gum_script_handle_replace_argument (GumScript * self,
                                    GScanner * scanner)
{
  GumCodeWriter * cw = &self->priv->code_writer;
  gulong argument_index;
  gchar * operation_name = NULL;

  if (g_scanner_get_next_token (scanner) != G_TOKEN_INT)
  {
    g_scanner_unexp_token (scanner, G_TOKEN_INT, NULL, NULL, NULL,
        "expected argument index", TRUE);
    goto error;
  }

  argument_index = scanner->value.v_int;

  if (g_scanner_get_next_token (scanner) != G_TOKEN_IDENTIFIER)
  {
    g_scanner_unexp_token (scanner, G_TOKEN_IDENTIFIER, NULL, NULL, NULL,
        "expected operation name to follow argument index", TRUE);
    goto error;
  }

  operation_name = g_strdup (scanner->value.v_string);

  if (strcmp (operation_name, "AddressOf") == 0 ||
      strcmp (operation_name, "LengthOf") == 0)
  {
    GumVariable * var;

    if (g_scanner_get_next_token (scanner) != G_TOKEN_IDENTIFIER)
    {
      g_scanner_unexp_token (scanner, G_TOKEN_IDENTIFIER, NULL, NULL, NULL,
          "expected variable name", TRUE);
      goto error;
    }

    var = gum_script_find_variable_named (self, scanner->value.v_string);
    if (var == NULL)
    {
      g_scanner_error (scanner, "referenced variable %s does not exist",
          scanner->value.v_string);
      goto error;
    }

    g_assert (var->type == GUM_VARIABLE_WIDE_STRING);

    if (operation_name[0] == 'A')
      gum_code_writer_put_mov_eax (cw, (guint32) var->value.wide_string);
    else
      gum_code_writer_put_mov_eax (cw, (guint32) var->value.string_length);

    gum_code_writer_put_mov_ecx_esp_offset_ptr (cw,
        GUM_SCRIPT_ESP_OFFSET_TO_STACK_ARGS);
    gum_code_writer_put_mov_reg_offset_ptr_reg (cw, GUM_REG_ECX,
        (gint8) (argument_index * sizeof (gpointer)), GUM_REG_EAX);
  }
  else
  {
    g_scanner_error (scanner, "unknown operation");
    goto error;
  }

  g_free (operation_name);
  return TRUE;

error:
  g_free (operation_name);
  return FALSE;
}

static GumVariable *
gum_script_add_wide_string_variable (GumScript * self,
                                     const gchar * name,
                                     const gchar * value_utf8)
{
  GumVariable * var;

  var = gum_script_add_variable (self, name, GUM_VARIABLE_WIDE_STRING);
  var->value.wide_string = g_utf8_to_utf16 (value_utf8, -1, NULL, NULL, NULL);
  var->value.string_length = g_utf8_strlen (value_utf8, -1);

  return var;
}

static GumVariable *
gum_script_add_variable (GumScript * self,
                         const gchar * name,
                         GumVariableType type)
{
  GumVariable * var;

  var = gum_variable_new (type);
  g_hash_table_insert (self->priv->variable_by_name, g_strdup (name),
      var);

  return var;
}

static gboolean
gum_script_has_variable_named (GumScript * self,
                               const gchar * name)
{
  return g_hash_table_lookup (self->priv->variable_by_name, name) != NULL;
}

static GumVariable *
gum_script_find_variable_named (GumScript * self,
                                const gchar * name)
{
  return (GumVariable *)
      g_hash_table_lookup (self->priv->variable_by_name, name);
}

static GumVariable *
gum_variable_new (GumVariableType type)
{
  GumVariable * var;

  var = g_slice_new0 (GumVariable);
  var->type = type;

  return var;
}

static void
gum_variable_free (GumVariable * var)
{
  g_free (var->value.ansi_string);
  g_free (var->value.wide_string);

  g_slice_free (GumVariable, var);
}

static void
gum_script_handle_parse_error (GScanner * scanner,
                               gchar * message,
                               gboolean error)
{
  GString * parse_messages = (GString *) scanner->user_data;

  if (parse_messages->len != 0)
    g_string_append_c (parse_messages, '\n');

  g_string_append (parse_messages, message);
}

static void
gum_script_init_scanner_config (GScannerConfig * scanner_config)
{
  memset (scanner_config, 0, sizeof (GScannerConfig));

  scanner_config->cset_skip_characters = " \t\n";
  scanner_config->cset_identifier_first = G_CSET_a_2_z "_" G_CSET_A_2_Z;
  scanner_config->cset_identifier_nth = G_CSET_a_2_z "_0123456789" G_CSET_A_2_Z
      G_CSET_LATINS G_CSET_LATINC;
  scanner_config->cpair_comment_single = "#\n";

  scanner_config->case_sensitive = TRUE;

  scanner_config->skip_comment_multi = TRUE;
  scanner_config->skip_comment_single = TRUE;
  scanner_config->scan_comment_multi = TRUE;
  scanner_config->scan_identifier = TRUE;
  scanner_config->scan_identifier_1char = FALSE;
  scanner_config->scan_identifier_NULL = FALSE;
  scanner_config->scan_symbols = TRUE;
  scanner_config->scan_binary = TRUE;
  scanner_config->scan_octal = TRUE;
  scanner_config->scan_float = TRUE;
  scanner_config->scan_hex = TRUE;
  scanner_config->scan_hex_dollar = FALSE;
  scanner_config->scan_string_sq = TRUE;
  scanner_config->scan_string_dq = TRUE;
  scanner_config->numbers_2_int = TRUE;
  scanner_config->int_2_float = FALSE;
  scanner_config->identifier_2_string = FALSE;
  scanner_config->char_2_token = TRUE;
  scanner_config->symbol_2_token = FALSE;
  scanner_config->scope_0_fallback = FALSE;
  scanner_config->store_int64 = FALSE;
}
