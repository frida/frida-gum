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

#include "gummemory.h"
#include "gumscript-priv.h"
#include "gumscriptcompiler.h"

#include <string.h>
#include <gio/gio.h> /* FIXME: piggy-backing on IOError for now */
#ifdef G_OS_WIN32
#define VC_EXTRALEAN
#include <windows.h>
#endif

typedef struct _GumVariable GumVariable;

typedef struct _GumFormatStringToken GumFormatStringToken;

struct _GumScriptPrivate
{
  GHashTable * variable_by_name;

  GumScriptEntrypoint entrypoint;

  guint8 * code;
  guint code_size;

  GString * send_arg_type_signature;
  GArray * send_arg_items;

  GumScriptMessageHandler message_handler_func;
  gpointer message_handler_data;
  GDestroyNotify message_handler_notify;
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

struct _GumFormatStringToken
{
  const gchar * begin;
  const gchar * end;
  guint length;

  gboolean width_in_argument;
  gboolean precision_in_argument;
  gchar specifier;
  guint value_size;
};

static void gum_script_finalize (GObject * object);

static gboolean gum_script_handle_variable_declaration (GumScript * self,
    GScanner * scanner);
static gboolean gum_script_handle_replace_argument (GumScript * self,
    GScanner * scanner, GumScriptCompiler * compiler);
static gboolean gum_script_handle_send_statement (GumScript * self,
    GScanner * scanner);
static void gum_script_generate_call_to_send_item_commit (GumScript * self,
    GScanner * scanner, GumScriptCompiler * compiler);

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

static void gum_script_expand_format_string (gchar ** format_str,
    gboolean is_wide, GumInvocationContext * context,
    guint first_format_argument_index);
static guint64 gum_consume_format_string_arg_value (
    const GumFormatStringToken * token, GumInvocationContext * context,
    guint * arg_index, gpointer * temporary_storage);

static void gum_describe_format_string_token (const gchar * token_start,
    GumFormatStringToken * token);
static void gum_format_string_pointer_skip_flags (const gchar ** p);
static void gum_format_string_pointer_skip_width (const gchar ** p,
    gboolean * specified_in_argument);
static void gum_format_string_pointer_skip_precision (const gchar ** p,
    gboolean * specified_in_argument);
static void gum_format_string_pointer_skip_length (const gchar ** p,
    guint * value_size);

static gchar * gum_narrow_string_to_utf8 (const gchar * str_narrow);

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

  priv->code = (guint8 *) gum_alloc_n_pages (1, GUM_PAGE_RW);

  priv->send_arg_items = g_array_new (FALSE, FALSE, sizeof (GumSendArgItem));
  priv->send_arg_type_signature = g_string_new ("");
}

static void
gum_script_finalize (GObject * object)
{
  GumScript * self = GUM_SCRIPT (object);
  GumScriptPrivate * priv = self->priv;

  if (priv->message_handler_notify != NULL)
    priv->message_handler_notify (priv->message_handler_data);

  g_string_free (priv->send_arg_type_signature, TRUE);
  g_array_free (priv->send_arg_items, TRUE);

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
  GumScriptCompiler compiler;
  GScannerConfig scanner_config = { 0, };
  GScanner * scanner;
  GString * parse_messages;
  guint start_offset;

  script = GUM_SCRIPT (g_object_new (GUM_TYPE_SCRIPT, NULL));
  priv = script->priv;

  gum_script_compiler_init (&compiler, priv->code);

  gum_script_init_scanner_config (&scanner_config);

  scanner = g_scanner_new (&scanner_config);

  parse_messages = g_string_new ("");
  scanner->msg_handler = gum_script_handle_parse_error;
  scanner->user_data = parse_messages;

  g_scanner_input_text (scanner, script_text, (guint) strlen (script_text));

  gum_script_compiler_emit_prologue (&compiler);

  start_offset = gum_script_compiler_current_offset (&compiler);

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
      statement_is_valid = gum_script_handle_replace_argument (script, scanner,
          &compiler);
    }
    else if (g_str_has_prefix (statement_type, "Send"))
    {
      statement_is_valid = gum_script_handle_send_statement (script, scanner);
    }
    else
    {
      g_scanner_error (scanner, "unexpected statement: '%s'", statement_type);
      statement_is_valid = FALSE;
    }

    if (!statement_is_valid)
      goto parse_error;
  }

  gum_script_generate_call_to_send_item_commit (script, scanner, &compiler);

  if (gum_script_compiler_current_offset (&compiler) == start_offset)
  {
    g_scanner_error (scanner, "script without any statements");
    goto parse_error;
  }

  gum_script_compiler_emit_epilogue (&compiler);

  gum_script_compiler_flush (&compiler);
  priv->entrypoint = gum_script_compiler_get_entrypoint (&compiler);
  priv->code_size = gum_script_compiler_current_offset (&compiler);

  gum_script_compiler_free (&compiler);

  gum_mprotect (priv->code, gum_query_page_size (), GUM_PAGE_RX);

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
    gum_script_compiler_free (&compiler);
    g_object_unref (script);

    return NULL;
  }
}

void
gum_script_set_message_handler (GumScript * self,
                                GumScriptMessageHandler func,
                                gpointer data,
                                GDestroyNotify notify)
{
  self->priv->message_handler_func = func;
  self->priv->message_handler_data = data;
  self->priv->message_handler_notify = notify;
}

void
gum_script_execute (GumScript * self,
                    GumInvocationContext * context)
{
  self->priv->entrypoint (context);
}

gpointer
gum_script_get_code_address (GumScript * self)
{
  return self->priv->code;
}

guint
gum_script_get_code_size (GumScript * self)
{
  return self->priv->code_size;
}

void
_gum_script_send_item_commit (GumScript * self,
                              GumInvocationContext * context,
                              guint argument_index,
                              ...)
{
  GumScriptPrivate * priv = self->priv;
  GVariantType * variant_type;
  GVariantBuilder * builder;
  va_list args;

  variant_type = g_variant_type_new (priv->send_arg_type_signature->str);
  builder = g_variant_builder_new (variant_type);

  va_start (args, argument_index);

  while (argument_index != G_MAXUINT)
  {
    gpointer argument_value;
    GumVariableType var_type;
    GVariant * value;

    argument_value =
        gum_invocation_context_get_nth_argument (context, argument_index);
    var_type = va_arg (args, GumVariableType);

    switch (var_type)
    {
      case GUM_VARIABLE_INT32:
        value = g_variant_new_int32 ((gint32) argument_value);
        break;

      case GUM_VARIABLE_ANSI_STRING:
      case GUM_VARIABLE_ANSI_FORMAT_STRING:
      {
        gchar * str_narrow;
        gchar * str_utf8;

        str_narrow = (gchar *) argument_value;
        str_utf8 = gum_narrow_string_to_utf8 (str_narrow);

        if (var_type == GUM_VARIABLE_ANSI_FORMAT_STRING)
        {
          gum_script_expand_format_string (&str_utf8, FALSE,
              context, argument_index + 1);
        }

        value = g_variant_new_string (str_utf8);

        g_free (str_utf8);

        break;
      }

      case GUM_VARIABLE_WIDE_STRING:
      case GUM_VARIABLE_WIDE_FORMAT_STRING:
      {
        gchar * str_utf8;

        str_utf8 = g_utf16_to_utf8 ((gunichar2 *) argument_value, -1,
            NULL, NULL, NULL);

        if (var_type == GUM_VARIABLE_WIDE_FORMAT_STRING)
        {
          gum_script_expand_format_string (&str_utf8, TRUE,
              context, argument_index + 1);
        }

        value = g_variant_new_string (str_utf8);

        g_free (str_utf8);

        break;
      }

      default:
        value = NULL;
        g_assert_not_reached ();
    }

    g_variant_builder_add_value (builder, value);

    argument_index = va_arg (args, guint);
  }

  va_end (args);

  priv->message_handler_func (self, g_variant_builder_end (builder),
      priv->message_handler_data);

  g_variant_type_free (variant_type);
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
                                    GScanner * scanner,
                                    GumScriptCompiler * compiler)
{
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
    GumAddress value;

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
      value = GUM_ADDRESS (var->value.wide_string);
    else
      value = GUM_ADDRESS (var->value.string_length);

    gum_script_compiler_emit_replace_argument (compiler, argument_index, value);
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

static gboolean
gum_script_handle_send_statement (GumScript * self,
                                  GScanner * scanner)
{
  const gchar * statement_type = scanner->value.v_string;
  GumSendArgItem item;
  gchar type_char;

  if (strcmp (statement_type, "SendInt32FromArgument") == 0)
  {
    item.type = GUM_VARIABLE_INT32;
    type_char = 'i';
  }
  else if (strcmp (statement_type, "SendNarrowStringFromArgument") == 0)
  {
    item.type = GUM_VARIABLE_ANSI_STRING;
    type_char = 's';
  }
  else if (strcmp (statement_type, "SendWideStringFromArgument") == 0)
  {
    item.type = GUM_VARIABLE_WIDE_STRING;
    type_char = 's';
  }
  else if (strcmp (statement_type, "SendNarrowFormatStringFromArgument") == 0)
  {
    item.type = GUM_VARIABLE_ANSI_FORMAT_STRING;
    type_char = 's';
  }
  else if (strcmp (statement_type, "SendWideFormatStringFromArgument") == 0)
  {
    item.type = GUM_VARIABLE_WIDE_FORMAT_STRING;
    type_char = 's';
  }
  else
  {
    g_scanner_error (scanner, "unexpected statement: '%s'", statement_type);
    goto error;
  }

  if (g_scanner_get_next_token (scanner) != G_TOKEN_INT)
  {
    g_scanner_unexp_token (scanner, G_TOKEN_INT, NULL, NULL, NULL,
        "expected argument index", TRUE);
    goto error;
  }
  item.index = scanner->value.v_int;

  g_string_append_c (self->priv->send_arg_type_signature, type_char);
  g_array_append_val (self->priv->send_arg_items, item);

  return TRUE;

error:
  return FALSE;
}

static void
gum_script_generate_call_to_send_item_commit (GumScript * self,
                                              GScanner * scanner,
                                              GumScriptCompiler * compiler)
{
  if (self->priv->send_arg_items->len == 0)
    return;

  g_string_insert_c (self->priv->send_arg_type_signature, 0, '(');
  g_string_append_c (self->priv->send_arg_type_signature, ')');

  gum_script_compiler_emit_send_item_commit (compiler, self,
      self->priv->send_arg_items);
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
  g_free (var->value.narrow_string);
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

static void
gum_script_expand_format_string (gchar ** format_str,
                                 gboolean is_wide,
                                 GumInvocationContext * context,
                                 guint first_format_argument_index)
{
  GString * str;
  const gchar * p;
  guint arg_index = first_format_argument_index;

  str = g_string_sized_new (2 * strlen (*format_str));

  for (p = *format_str; *p != '\0';)
  {
    GumFormatStringToken t;

    if (p[0] != '%')
    {
      g_string_append_c (str, p[0]);
      p++;
      continue;
    }
    else if (p[1] == '%')
    {
      g_string_append_c (str, p[0]);
      p += 2;
      continue;
    }

    gum_describe_format_string_token (p, &t);

    if (t.specifier == 's' && is_wide)
      t.specifier = 'S';
    else if (t.specifier == 'S' && is_wide)
      t.specifier = 's';

    if (t.specifier == 'n')
    {
      gint * n_characters_written_so_far;

      n_characters_written_so_far = (gint *)
          gum_invocation_context_get_nth_argument (context, arg_index);
      *n_characters_written_so_far = (gint) g_utf8_strlen (str->str, -1);

      arg_index++;
    }
    else
    {
      gchar temp_format[16];
      guint64 value;
      gpointer temporary_storage;

      memcpy (temp_format, t.begin, t.length);
      temp_format[t.length] = '\0';

      if (t.width_in_argument && t.precision_in_argument)
      {
        gint width, precision;

        width = (gint)
            gum_invocation_context_get_nth_argument (context, arg_index + 0);
        precision = (gint)
            gum_invocation_context_get_nth_argument (context, arg_index + 1);
        arg_index += 2;

        value = gum_consume_format_string_arg_value (&t, context, &arg_index,
            &temporary_storage);

        g_string_append_printf (str, temp_format, width, precision, value);
      }
      else if (t.width_in_argument || t.precision_in_argument)
      {
        gint width_or_precision;

        width_or_precision = (gint)
            gum_invocation_context_get_nth_argument (context, arg_index + 0);
        arg_index++;

        value = gum_consume_format_string_arg_value (&t, context, &arg_index,
            &temporary_storage);
        g_string_append_printf (str, temp_format, width_or_precision, value);
      }
      else
      {
        value = gum_consume_format_string_arg_value (&t, context, &arg_index,
            &temporary_storage);
        g_string_append_printf (str, temp_format, value);
      }

      g_free (temporary_storage);
    }

    p = t.end;
  }

  g_free (*format_str);
  *format_str = g_string_free (str, FALSE);
}

static guint64
gum_consume_format_string_arg_value (const GumFormatStringToken * token,
                                     GumInvocationContext * context,
                                     guint * arg_index,
                                     gpointer * temporary_storage)
{
  guint64 value;

  value = (guint64) GPOINTER_TO_SIZE (
      gum_invocation_context_get_nth_argument (context, *arg_index));
  (*arg_index)++;

  switch (token->value_size)
  {
    case 1: value &= 0x000000ff; break;
    case 2: value &= 0x0000ffff; break;
    case 4: value &= 0xffffffff; break;

    case 8:
#if GLIB_SIZEOF_VOID_P == 4
      {
        guint64 high_value;

        high_value = (guint64) GPOINTER_TO_SIZE (
            gum_invocation_context_get_nth_argument (context, *arg_index));
        (*arg_index)++;

        value |= (high_value << 32);
      }
#endif
      break;

    default:
      g_assert_not_reached ();
  }

  if (token->specifier == 's')
  {
    const gchar * str_narrow;

    str_narrow = (const gchar *) GSIZE_TO_POINTER (value);
    *temporary_storage = gum_narrow_string_to_utf8 (str_narrow);
    value = (guint64) GPOINTER_TO_SIZE (*temporary_storage);
  }
  else if (token->specifier == 'S')
  {
    const gunichar2 * str_utf16;

    str_utf16 = (const gunichar2 *) GSIZE_TO_POINTER (value);
    *temporary_storage = g_utf16_to_utf8 (str_utf16, -1, NULL, NULL, NULL);
    value = (guint64) GPOINTER_TO_SIZE (*temporary_storage);
  }
  else
  {
    *temporary_storage = NULL;
  }

  return value;
}

static void
gum_describe_format_string_token (const gchar * token_start,
                                  GumFormatStringToken * token)
{
  const gchar * p;

  g_assert (*token_start == '%');

  p = token_start + 1;
  gum_format_string_pointer_skip_flags (&p);
  gum_format_string_pointer_skip_width (&p, &token->width_in_argument);
  gum_format_string_pointer_skip_precision (&p, &token->precision_in_argument);
  gum_format_string_pointer_skip_length (&p, &token->value_size);
  token->specifier = *p;

  token->begin = token_start;
  token->end = p + 1;
  token->length = token->end - token->begin;

  switch (token->specifier)
  {
    case 'c':
      token->value_size = 1;
      break;

    case 'd':
    case 'e':
    case 'E':
    case 'f':
    case 'g':
    case 'G':
    case 'o':
    case 'u':
    case 'x':
    case 'X':
      if (token->value_size == 0)
        token->value_size = 4;
      break;

    case 'p':        
    case 's':
    case 'n':
      token->value_size = GLIB_SIZEOF_VOID_P;
      break;

    default:
      g_assert_not_reached ();
  }
}

static void
gum_format_string_pointer_skip_flags (const gchar ** p)
{
  switch (**p)
  {
    case '-':
    case '+':
    case ' ':
    case '#':
    case '0':
      (*p)++;

    default:
      break;
  }
}

static void
gum_format_string_pointer_skip_width (const gchar ** p,
                                      gboolean * specified_in_argument)
{
  const gchar * cur = *p;

  if (*cur == '*')
  {
    *specified_in_argument = TRUE;

    cur++;
  }
  else
  {
    *specified_in_argument = FALSE;

    while (g_ascii_isdigit (*cur))
      cur++;
  }

  *p = cur;
}

static void
gum_format_string_pointer_skip_precision (const gchar ** p,
                                          gboolean * specified_in_argument)
{
  const gchar * cur = *p;

  *specified_in_argument = FALSE;

  if (*cur != '.')
    return;
  cur++;

  if (*cur == '*')
  {
    *specified_in_argument = TRUE;

    cur++;
  }
  else
  {
    while (g_ascii_isdigit (*cur))
      cur++;
  }

  *p = cur;
}

static void
gum_format_string_pointer_skip_length (const gchar ** p,
                                       guint * value_size)
{
  switch (**p)
  {
    case 'h':
      *value_size = 2;
      break;

    case 'l':
      *value_size = 4;
      break;

    case 'L':
      *value_size = 8;
      break;

    default:
      *value_size = 0;
      break;
  }

  if (*value_size != 0)
    (*p)++;
}

static gchar *
gum_narrow_string_to_utf8 (const gchar * str_narrow)
{
#ifdef G_OS_WIN32
  guint str_wide_size;
  WCHAR * str_wide;
  gchar * str_utf8;

  str_wide_size = (guint) (strlen (str_narrow) + 1) * sizeof (WCHAR);
  str_wide = (WCHAR *) g_malloc (str_wide_size);
  MultiByteToWideChar (CP_ACP, 0, str_narrow, -1, str_wide, str_wide_size);
  str_utf8 = g_utf16_to_utf8 ((gunichar2 *) str_wide, -1, NULL, NULL, NULL);
  g_free (str_wide);

  return str_utf8;
#else
  return g_strdup (str_narrow);
#endif
}
