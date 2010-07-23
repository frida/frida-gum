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
#ifdef G_OS_WIN32
#define VC_EXTRALEAN
#include <windows.h>
#endif

#define GUM_SCRIPT_DEFAULT_LOCALS_CAPACITY 64

#if GLIB_SIZEOF_VOID_P == 4
#define GUM_SCRIPT_ENTRYPOINT_API __fastcall
#else
#define GUM_SCRIPT_ENTRYPOINT_API
#endif

typedef enum _GumVariableType GumVariableType;
typedef struct _GumVariable GumVariable;

typedef struct _GumSendArgItem GumSendArgItem;

typedef void (GUM_SCRIPT_ENTRYPOINT_API * GumScriptEntrypoint)
    (GumInvocationContext * ctx);

struct _GumScriptPrivate
{
  GHashTable * variable_by_name;

  GumScriptEntrypoint entrypoint;

  guint8 * code;
  GumCodeWriter code_writer;

  GString * send_arg_type_signature;
  GArray * send_arg_items;

  GumScriptMessageHandler message_handler_func;
  gpointer message_handler_data;
  GDestroyNotify message_handler_notify;
};

enum _GumVariableType
{
  GUM_VARIABLE_INT32,
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

struct _GumSendArgItem
{
  guint index;
  GumVariableType type;
};

static void gum_script_finalize (GObject * object);

static gboolean gum_script_handle_variable_declaration (GumScript * self,
    GScanner * scanner);
static gboolean gum_script_handle_replace_argument (GumScript * self,
    GScanner * scanner);
static gboolean gum_script_handle_send_statement (GumScript * self,
    GScanner * scanner);
static void gum_script_generate_call_to_send_item_commit (GumScript * self,
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
  GumCodeWriter * cw;
  GScannerConfig scanner_config = { 0, };
  GScanner * scanner;
  GString * parse_messages;
  guint start_offset;

  script = GUM_SCRIPT (g_object_new (GUM_TYPE_SCRIPT, NULL));
  priv = script->priv;
  cw = &priv->code_writer;

  gum_script_init_scanner_config (&scanner_config);

  scanner = g_scanner_new (&scanner_config);

  parse_messages = g_string_new ("");
  scanner->msg_handler = gum_script_handle_parse_error;
  scanner->user_data = parse_messages;

  g_scanner_input_text (scanner, script_text, (guint) strlen (script_text));

  gum_code_writer_put_push_reg (cw, GUM_REG_XBP);
  gum_code_writer_put_mov_reg_reg (cw, GUM_REG_XBP, GUM_REG_XSP);
  gum_code_writer_put_sub_reg_imm (cw, GUM_REG_XSP, sizeof (gpointer));

  gum_code_writer_put_push_reg (cw, GUM_REG_XBX);
  gum_code_writer_put_mov_reg_reg (cw, GUM_REG_XBX, GUM_REG_XCX);

  start_offset = gum_code_writer_offset (cw);

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

  gum_script_generate_call_to_send_item_commit (script, scanner);

  if (gum_code_writer_offset (&priv->code_writer) == start_offset)
  {
    g_scanner_error (scanner, "script without any statements");
    goto parse_error;
  }

  gum_code_writer_put_pop_reg (cw, GUM_REG_XBX);

  gum_code_writer_put_mov_reg_reg (cw, GUM_REG_XSP, GUM_REG_XBP);
  gum_code_writer_put_pop_reg (cw, GUM_REG_XBP);
  gum_code_writer_put_ret (cw);

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
                    GumInvocationContext * ctx)
{
  self->priv->entrypoint (ctx);
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

static void
gum_script_send_item_commit (GumScript * self,
                             GumInvocationContext * ctx,
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
        gum_invocation_context_get_nth_argument (ctx, argument_index);
    var_type = va_arg (args, GumVariableType);

    switch (var_type)
    {
      case GUM_VARIABLE_INT32:
        value = g_variant_new_int32 ((gint32) argument_value);
        break;

      case GUM_VARIABLE_ANSI_STRING:
      {
        gchar * str_ansi;
        guint str_wide_size;
        WCHAR * str_wide;
        gchar * str_utf8;

        str_ansi = (gchar *) argument_value;

        str_wide_size = (guint) (strlen (str_ansi) + 1) * sizeof (WCHAR);
        str_wide = (WCHAR *) g_malloc (str_wide_size);
        MultiByteToWideChar (CP_ACP, 0, str_ansi, -1, str_wide, str_wide_size);
        str_utf8 = g_utf16_to_utf8 ((gunichar2 *) str_wide, -1, NULL, NULL, NULL);

        value = g_variant_new_string (str_utf8);

        g_free (str_utf8);
        g_free (str_wide);

        break;
      }

      case GUM_VARIABLE_WIDE_STRING:
      {
        gchar * str_utf8;

        str_utf8 = g_utf16_to_utf8 ((gunichar2 *) argument_value, -1,
            NULL, NULL, NULL);
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

    gum_code_writer_put_push_reg (cw, GUM_REG_XSI);

    if (operation_name[0] == 'A')
    {
      gum_code_writer_put_mov_reg_address (cw, GUM_REG_XSI,
          GUM_ADDRESS (var->value.wide_string));
    }
    else
    {
      gum_code_writer_put_mov_reg_address (cw, GUM_REG_XSI,
          GUM_ADDRESS (var->value.string_length));
    }

    gum_code_writer_put_call_with_arguments (cw,
        gum_invocation_context_replace_nth_argument, 3,
        GUM_ARG_REGISTER, GUM_REG_XBX,
        GUM_ARG_POINTER, GSIZE_TO_POINTER (argument_index),
        GUM_ARG_REGISTER, GUM_REG_XSI);

    gum_code_writer_put_pop_reg (cw, GUM_REG_XSI);
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
  GumCodeWriter * cw = &self->priv->code_writer;
  const gchar * statement_type = scanner->value.v_string;
  GumSendArgItem item;
  gchar type_char;

  if (strcmp (statement_type, "SendInt32FromArgument") == 0)
  {
    item.type = GUM_VARIABLE_INT32;
    type_char = 'i';
  }
  else if (strcmp (statement_type, "SendAnsiStringFromArgument") == 0)
  {
    item.type = GUM_VARIABLE_ANSI_STRING;
    type_char = 's';
  }
  else if (strcmp (statement_type, "SendWideStringFromArgument") == 0)
  {
    item.type = GUM_VARIABLE_WIDE_STRING;
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
                                              GScanner * scanner)
{
  GumCodeWriter * cw = &self->priv->code_writer;
  GArray * items = self->priv->send_arg_items;
  gint item_index;

  if (items->len == 0)
    return;

  g_string_insert_c (self->priv->send_arg_type_signature, 0, '(');
  g_string_append_c (self->priv->send_arg_type_signature, ')');

  gum_code_writer_put_push_u32 (cw, 0x9ADD176); /* alignment padding */
  gum_code_writer_put_push_u32 (cw, G_MAXUINT);

  for (item_index = items->len - 1; item_index >= 0; item_index--)
  {
    GumSendArgItem * item = &g_array_index (items, GumSendArgItem, item_index);

#if GLIB_SIZEOF_VOID_P == 8
    if (item_index == 0)
    {
      gum_code_writer_put_mov_reg_u32 (cw, GUM_REG_R9D, item->type);
      gum_code_writer_put_mov_reg_u32 (cw, GUM_REG_R8D, item->index);
    }
    else
#endif
    {
      gum_code_writer_put_push_u32 (cw, item->type);
      gum_code_writer_put_push_u32 (cw, item->index);
    }
  }

#if GLIB_SIZEOF_VOID_P == 8
  gum_code_writer_put_mov_reg_reg (cw, GUM_REG_RDX, GUM_REG_RBX);
  gum_code_writer_put_mov_reg_address (cw, GUM_REG_RCX, GUM_ADDRESS (self));
  gum_code_writer_put_sub_reg_imm (cw, GUM_REG_RSP, 4 * sizeof (gpointer));
#else
  gum_code_writer_put_push_reg (cw, GUM_REG_EBX);
  gum_code_writer_put_push_u32 (cw, (guint32) self);
#endif

  gum_code_writer_put_call (cw, gum_script_send_item_commit);

  gum_code_writer_put_add_reg_imm (cw, GUM_REG_XSP,
      (2 + (items->len * 2) + 2) * sizeof (gpointer));
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
