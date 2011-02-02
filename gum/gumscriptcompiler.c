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

#include "gumscriptcompiler.h"

#include "gummemory.h"

#include <stdlib.h>
#include <string.h>
#include <gio/gio.h> /* FIXME: piggy-backing on IOError for now */

typedef struct _GumScriptCompiler GumScriptCompiler;
typedef struct _GumVariable GumVariable;

struct _GumScriptCompiler
{
  GScannerConfig scanner_config;
  GScanner * scanner;
  GString * parse_messages;

  GHashTable * variable_by_name;

  GString * send_arg_type_signature;
  GArray * send_arg_items;

  GumScriptCode * code;
  GumScriptData * data;
  GumScriptCompilerBackend * backend;

  GumScript * script;
};

struct _GumVariable
{
  GumVariableType type;

  struct
  {
    gchar * narrow_string;
    gunichar2 * wide_string;
    guint string_length;
  } value;
};

static void gum_script_compiler_init (GumScriptCompiler * self);
static void gum_script_compiler_destroy (GumScriptCompiler * self);
static GumScript * gum_script_compiler_process (GumScriptCompiler * self,
    const gchar * script_text, GError ** error);

static GumScriptEntrypoint gum_script_compiler_open_function (
    GumScriptCompiler * self);
static void gum_script_compiler_close_function (GumScriptCompiler * self);
static gboolean gum_script_compiler_handle_replace_argument (
    GumScriptCompiler * self, guint argument_index);
static gboolean gum_script_compiler_handle_send_statement (
    GumScriptCompiler * self);
static gboolean gum_script_compiler_handle_variable_declaration (
    GumScriptCompiler * self);
static gboolean gum_script_compiler_handle_assignment (
    GumScriptCompiler * self, const gchar * variable_name);
static gboolean gum_script_compiler_handle_arg_variable_reference (
    GumScriptCompiler * self, guint * argument_index);
static gboolean gum_script_compiler_handle_open_parentheses (
    GumScriptCompiler * self);
static gboolean gum_script_compiler_handle_close_parentheses (
    GumScriptCompiler * self);
static gboolean gum_script_compiler_handle_comma (GumScriptCompiler * self);
static void gum_script_compiler_generate_call_to_send_item_commit (
    GumScriptCompiler * self);

static GumVariable * gum_script_compiler_add_wide_string_variable (
    GumScriptCompiler * self, const gchar * name, const gchar * value_utf8);
static GumVariable * gum_script_compiler_add_variable (
    GumScriptCompiler * self, const gchar * name, GumVariableType type);
static gboolean gum_script_compiler_has_variable_named (
    GumScriptCompiler * self, const gchar * name);
static GumVariable * gum_script_compiler_find_variable_named (
    GumScriptCompiler * self, const gchar * name);

static GumVariable * gum_variable_new (GumVariableType type);
static void gum_variable_free (GumVariable * var);

static void gum_script_compiler_handle_parse_error (GScanner * scanner,
    gchar * message, gboolean error);
static void gum_script_compiler_init_scanner_config (
    GScannerConfig * scanner_config);

GumScript *
gum_script_compiler_compile (const gchar * script_text,
                             GError ** error)
{
  GumScriptCompiler compiler;
  GumScript * script;

  gum_script_compiler_init (&compiler);
  script = gum_script_compiler_process (&compiler, script_text, error);
  gum_script_compiler_destroy (&compiler);

  return script;
}

static GumScriptCode *
gum_script_code_new (void)
{
  GumScriptCode * code;

  code = g_slice_new0 (GumScriptCode);
  code->start = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RW);

  return code;
}

void
gum_script_code_free (GumScriptCode * code)
{
  gum_free_pages (code->start);

  g_slice_free (GumScriptCode, code);
}

static GumScriptData *
gum_script_data_new (void)
{
  return g_slice_new0 (GumScriptData);
}

void
gum_script_data_free (GumScriptData * data)
{
  g_hash_table_unref (data->variable_by_name);
  g_free (data->send_arg_type_signature[0]);
  g_free (data->send_arg_type_signature[1]);

  g_slice_free (GumScriptData, data);
}

static void
gum_script_compiler_init (GumScriptCompiler * self)
{
  gum_script_compiler_init_scanner_config (&self->scanner_config);
  self->scanner = g_scanner_new (&self->scanner_config);
  self->parse_messages = g_string_new ("");
  self->scanner->msg_handler = gum_script_compiler_handle_parse_error;
  self->scanner->user_data = self->parse_messages;

  self->variable_by_name = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) gum_variable_free);

  self->send_arg_items = NULL;
  self->send_arg_type_signature = NULL;

  self->code = gum_script_code_new ();
  self->data = gum_script_data_new ();
  self->backend = gum_script_compiler_backend_new (self->code->start);

  self->script = GUM_SCRIPT (g_object_new (GUM_TYPE_SCRIPT, NULL));
}

static void
gum_script_compiler_destroy (GumScriptCompiler * self)
{
  g_scanner_destroy (self->scanner);
  g_string_free (self->parse_messages, TRUE);

  self->data->variable_by_name = self->variable_by_name;

  g_assert (self->send_arg_items == NULL);
  g_assert (self->send_arg_type_signature == NULL);
  self->script->priv->data = self->data;

  gum_script_compiler_backend_flush (self->backend);
  gum_mprotect (self->code->start, gum_query_page_size (), GUM_PAGE_RX);
  self->code->size =
      gum_script_compiler_backend_current_offset (self->backend);
  gum_clear_cache (self->code->start, self->code->size);
  self->script->priv->code = self->code;

  gum_script_compiler_backend_free (self->backend);

  g_object_unref (self->script);
}

static GumScript *
gum_script_compiler_process (GumScriptCompiler * self,
                             const gchar * script_text,
                             GError ** error)
{
  g_scanner_input_text (self->scanner, script_text,
      (guint) strlen (script_text));

  self->code->enter_entrypoint = gum_script_compiler_open_function (self);

  while (!g_scanner_eof (self->scanner))
  {
    GTokenType token_type;
    gboolean statement_is_valid;

    token_type = g_scanner_get_next_token (self->scanner);
    if (token_type == G_TOKEN_EOF)
      break;

    if (token_type == '-')
    {
      token_type = g_scanner_get_next_token (self->scanner);
      if (token_type == '-')
        token_type = g_scanner_get_next_token (self->scanner);
      if (token_type != '-')
      {
        g_scanner_unexp_token (self->scanner, (GTokenType) '-', NULL, NULL,
            NULL,
            "expected three consecutive dashes for separating enter and leave",
            TRUE);
        goto parse_error;
      }

      gum_script_compiler_close_function (self);

      self->code->leave_entrypoint = gum_script_compiler_open_function (self);

      continue;
    }

    if (token_type != G_TOKEN_IDENTIFIER)
    {
      g_scanner_unexp_token (self->scanner, G_TOKEN_IDENTIFIER, NULL, NULL,
          NULL, "expected statement", TRUE);
      goto parse_error;
    }

    if (g_scanner_peek_next_token (self->scanner) == G_TOKEN_EQUAL_SIGN)
    {
      gchar * variable_name;

      variable_name = g_strdup (self->scanner->value.v_string);
      g_scanner_get_next_token (self->scanner);
      statement_is_valid = gum_script_compiler_handle_assignment (self,
          variable_name);
      g_free (variable_name);
    }
    else
    {
      const gchar * statement_type;

      statement_type = self->scanner->value.v_string;
      if (strcmp (statement_type, "var") == 0)
      {
        statement_is_valid =
            gum_script_compiler_handle_variable_declaration (self);
      }
      else if (g_str_has_prefix (statement_type, "send_"))
      {
        statement_is_valid = gum_script_compiler_handle_send_statement (self);
      }
      else
      {
        g_scanner_error (self->scanner, "unexpected statement: '%s'",
            statement_type);
        statement_is_valid = FALSE;
      }
    }

    if (!statement_is_valid)
      goto parse_error;
  }

  gum_script_compiler_close_function (self);

  if (self->code->leave_entrypoint == NULL)
  {
    self->code->leave_entrypoint = gum_script_compiler_open_function (self);
    gum_script_compiler_close_function (self);
  }

  return GUM_SCRIPT (g_object_ref (self->script));

  /* ERRORS */
parse_error:
  {
    gum_script_compiler_close_function (self);

    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Parse error: %s", self->parse_messages->str);

    return NULL;
  }
}

static GumScriptEntrypoint
gum_script_compiler_open_function (GumScriptCompiler * self)
{
  GumScriptEntrypoint entrypoint;

  g_assert (self->send_arg_items == NULL);
  self->send_arg_items = g_array_new (FALSE, FALSE, sizeof (GumSendArgItem));
  g_assert (self->send_arg_type_signature == NULL);
  self->send_arg_type_signature = g_string_new ("");

  entrypoint = gum_script_compiler_backend_entrypoint_at (self->backend,
      gum_script_compiler_backend_current_offset (self->backend));
  gum_script_compiler_backend_emit_prologue (self->backend);

  return entrypoint;
}

static void
gum_script_compiler_close_function (GumScriptCompiler * self)
{
  gchar ** slot;

  gum_script_compiler_generate_call_to_send_item_commit (self);

  g_array_free (self->send_arg_items, TRUE);
  self->send_arg_items = NULL;
  slot = &self->data->send_arg_type_signature[0];
  if (*slot != NULL)
    slot++;
  g_assert (*slot == NULL);
  *slot = g_string_free (self->send_arg_type_signature, FALSE);
  self->send_arg_type_signature = NULL;

  gum_script_compiler_backend_emit_epilogue (self->backend);
  gum_script_compiler_backend_flush (self->backend);
}

static gboolean
gum_script_compiler_handle_replace_argument (GumScriptCompiler * self,
                                             guint argument_index)
{
  GTokenType operation_token;
  gboolean is_address_of = FALSE;
  GumVariable * var;
  GumAddress value;

  operation_token = g_scanner_get_next_token (self->scanner);
  if (operation_token == '&')
  {
    is_address_of = TRUE;
  }
  else
  {
    if (operation_token != G_TOKEN_IDENTIFIER)
    {
      g_scanner_unexp_token (self->scanner, G_TOKEN_IDENTIFIER, NULL, NULL,
          NULL, "expected operation to follow argument assignment", TRUE);
      goto error;
    }

    if (strcmp (self->scanner->value.v_identifier, "len") != 0)
    {
      g_scanner_error (self->scanner, "unknown operation");
      goto error;
    }
  }

  if (!is_address_of && !gum_script_compiler_handle_open_parentheses (self))
    goto error;

  if (g_scanner_get_next_token (self->scanner) != G_TOKEN_IDENTIFIER)
  {
    g_scanner_unexp_token (self->scanner, G_TOKEN_IDENTIFIER, NULL, NULL, NULL,
        "expected variable name", TRUE);
    goto error;
  }

  var = gum_script_compiler_find_variable_named (self,
      self->scanner->value.v_string);
  if (var == NULL)
  {
    g_scanner_error (self->scanner, "referenced variable %s does not exist",
        self->scanner->value.v_string);
    goto error;
  }

  g_assert (var->type == GUM_VARIABLE_WIDE_STRING);

  if (is_address_of)
    value = GUM_ADDRESS (var->value.wide_string);
  else
    value = GUM_ADDRESS (var->value.string_length);

  gum_script_compiler_backend_emit_replace_argument (self->backend,
      argument_index, value);

  if (!is_address_of && !gum_script_compiler_handle_close_parentheses (self))
    goto error;

  return TRUE;

error:
  return FALSE;
}

static gboolean
gum_script_compiler_handle_send_statement (GumScriptCompiler * self)
{
  const gchar * statement_type = self->scanner->value.v_string;
  GumSendArgItem item;
  gchar type_char;

  if (strcmp (statement_type, "send_int32") == 0)
  {
    item.type = GUM_VARIABLE_INT32;
    type_char = 'i';
  }
  else if (strcmp (statement_type, "send_narrow_string") == 0)
  {
    item.type = GUM_VARIABLE_ANSI_STRING;
    type_char = 's';
  }
  else if (strcmp (statement_type, "send_wide_string") == 0)
  {
    item.type = GUM_VARIABLE_WIDE_STRING;
    type_char = 's';
  }
  else if (strcmp (statement_type, "send_narrow_format_string") == 0)
  {
    item.type = GUM_VARIABLE_ANSI_FORMAT_STRING;
    type_char = 's';
  }
  else if (strcmp (statement_type, "send_wide_format_string") == 0)
  {
    item.type = GUM_VARIABLE_WIDE_FORMAT_STRING;
    type_char = 's';
  }
  else if (strcmp (statement_type, "send_byte_array") == 0)
  {
    item.type = GUM_VARIABLE_BYTE_ARRAY;
    type_char = ' ';
  }
  else if (strcmp (statement_type, "send_guid") == 0)
  {
    item.type = GUM_VARIABLE_GUID;
    type_char = 's';
  }
  else
  {
    g_scanner_error (self->scanner, "unexpected statement: '%s'",
        statement_type);
    goto error;
  }

  if (!gum_script_compiler_handle_open_parentheses (self))
    goto error;

  if (!gum_script_compiler_handle_arg_variable_reference (self, &item.index))
    goto error;

  if (item.type == GUM_VARIABLE_BYTE_ARRAY)
  {
    guint len_arg;

    if (!gum_script_compiler_handle_comma (self))
      goto error;

    if (!gum_script_compiler_handle_arg_variable_reference (self, &len_arg))
      goto error;
    item.index = (item.index << 16) | len_arg;
  }

  if (!gum_script_compiler_handle_close_parentheses (self))
    goto error;

  if (type_char == ' ')
    g_string_append (self->send_arg_type_signature, "ay");
  else
    g_string_append_c (self->send_arg_type_signature, type_char);
  g_array_append_val (self->send_arg_items, item);

  return TRUE;

error:
  return FALSE;
}

static gboolean
gum_script_compiler_handle_variable_declaration (GumScriptCompiler * self)
{
  GScanner * scanner = self->scanner;
  gchar * variable_name = NULL;
 
  if (g_scanner_get_next_token (scanner) != G_TOKEN_IDENTIFIER)
  {
    g_scanner_unexp_token (scanner, G_TOKEN_IDENTIFIER, NULL, NULL, NULL,
        "expected variable name", TRUE);
    goto error;
  }

  if (gum_script_compiler_has_variable_named (self, scanner->value.v_string))
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
          gum_script_compiler_add_wide_string_variable (self, variable_name,
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
gum_script_compiler_handle_assignment (GumScriptCompiler * self,
                                       const gchar * variable_name)
{
  guint argument_index;

  if (!g_str_has_prefix (variable_name, "arg"))
  {
    g_scanner_error (self->scanner, "only arguments can be assigned to");
    return FALSE;
  }
  argument_index = atoi (variable_name + 3);

  return gum_script_compiler_handle_replace_argument (self, argument_index);
}

static gboolean
gum_script_compiler_handle_arg_variable_reference (GumScriptCompiler * self,
                                                   guint * argument_index)
{
  if (g_scanner_get_next_token (self->scanner) != G_TOKEN_IDENTIFIER)
  {
    g_scanner_unexp_token (self->scanner, G_TOKEN_INT, NULL, NULL, NULL,
        "expected variable name", TRUE);
    return FALSE;
  }

  if (g_str_has_prefix (self->scanner->value.v_identifier, "arg"))
    *argument_index = 1 + atoi (self->scanner->value.v_identifier + 3);
  else if (strcmp (self->scanner->value.v_identifier, "retval") == 0)
    *argument_index = 0;
  else
    goto variable_does_not_exist;

  return TRUE;

  /* ERRORS */
variable_does_not_exist:
  {
    g_scanner_error (self->scanner, "referenced variable %s does not exist",
        self->scanner->value.v_identifier);
    return FALSE;
  }
}

static gboolean
gum_script_compiler_handle_open_parentheses (GumScriptCompiler * self)
{
  if (g_scanner_get_next_token (self->scanner) != G_TOKEN_LEFT_PAREN)
  {
    g_scanner_unexp_token (self->scanner, G_TOKEN_INT, NULL, NULL, NULL,
        "expected opening parentheses", TRUE);
    return FALSE;
  }

  return TRUE;
}

static gboolean
gum_script_compiler_handle_close_parentheses (GumScriptCompiler * self)
{
  if (g_scanner_get_next_token (self->scanner) != G_TOKEN_RIGHT_PAREN)
  {
    g_scanner_unexp_token (self->scanner, G_TOKEN_INT, NULL, NULL, NULL,
        "expected closing parentheses", TRUE);
    return FALSE;
  }

  return TRUE;
}

static gboolean
gum_script_compiler_handle_comma (GumScriptCompiler * self)
{
  if (g_scanner_get_next_token (self->scanner) != G_TOKEN_COMMA)
  {
    g_scanner_unexp_token (self->scanner, G_TOKEN_INT, NULL, NULL, NULL,
        "expected byte array length variable name", TRUE);
    return FALSE;
  }

  return TRUE;
}

static void
gum_script_compiler_generate_call_to_send_item_commit (
    GumScriptCompiler * self)
{
  if (self->send_arg_items->len == 0)
    return;

  g_string_insert_c (self->send_arg_type_signature, 0, '(');
  g_string_append_c (self->send_arg_type_signature, ')');

  gum_script_compiler_backend_emit_send_item_commit (self->backend,
      self->script, self->send_arg_items);
}

static GumVariable *
gum_script_compiler_add_wide_string_variable (GumScriptCompiler * self,
                                              const gchar * name,
                                              const gchar * value_utf8)
{
  GumVariable * var;

  var = gum_script_compiler_add_variable (self, name, GUM_VARIABLE_WIDE_STRING);
  var->value.wide_string = g_utf8_to_utf16 (value_utf8, -1, NULL, NULL, NULL);
  var->value.string_length = g_utf8_strlen (value_utf8, -1);

  return var;
}

static GumVariable *
gum_script_compiler_add_variable (GumScriptCompiler * self,
                                  const gchar * name,
                                  GumVariableType type)
{
  GumVariable * var;

  var = gum_variable_new (type);
  g_hash_table_insert (self->variable_by_name, g_strdup (name), var);

  return var;
}

static gboolean
gum_script_compiler_has_variable_named (GumScriptCompiler * self,
                                        const gchar * name)
{
  return g_hash_table_lookup (self->variable_by_name, name) != NULL;
}

static GumVariable *
gum_script_compiler_find_variable_named (GumScriptCompiler * self,
                                         const gchar * name)
{
  return (GumVariable *) g_hash_table_lookup (self->variable_by_name, name);
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
  g_free (var->value.narrow_string);
  g_free (var->value.wide_string);

  g_slice_free (GumVariable, var);
}

static void
gum_script_compiler_handle_parse_error (GScanner * scanner,
                                        gchar * message,
                                        gboolean error)
{
  GString * parse_messages = (GString *) scanner->user_data;

  (void) error;

  if (parse_messages->len != 0)
    g_string_append_c (parse_messages, '\n');

  g_string_append (parse_messages, message);
}

static void
gum_script_compiler_init_scanner_config (GScannerConfig * scanner_config)
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
