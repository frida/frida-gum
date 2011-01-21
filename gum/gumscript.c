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

#include "gumscript-priv.h"
#include "gumscriptcompiler.h"

#include <string.h>
#ifdef G_OS_WIN32
#define VC_EXTRALEAN
#include <windows.h>
#endif

typedef struct _GumFormatStringToken GumFormatStringToken;

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
}

static void
gum_script_finalize (GObject * object)
{
  GumScript * self = GUM_SCRIPT (object);
  GumScriptPrivate * priv = self->priv;

  if (priv->message_handler_notify != NULL)
    priv->message_handler_notify (priv->message_handler_data);

  gum_script_code_free (priv->code);
  gum_script_data_free (priv->data);

  G_OBJECT_CLASS (gum_script_parent_class)->finalize (object);
}

GumScript *
gum_script_from_string (const gchar * script_text,
                        GError ** error)
{
  return gum_script_compiler_compile (script_text, error);
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
  if (gum_invocation_context_get_point_cut (context) == GUM_POINT_ENTER)
    self->priv->code->enter_entrypoint (context);
  else
    self->priv->code->leave_entrypoint (context);
}

gpointer
gum_script_get_code_address (GumScript * self)
{
  return self->priv->code->start;
}

guint
gum_script_get_code_size (GumScript * self)
{
  return self->priv->code->size;
}

void
_gum_script_send_item_commit (GumScript * self,
                              GumInvocationContext * context,
                              guint argument_index,
                              ...)
{
  GumScriptPrivate * priv = self->priv;
  GumPointCut point_cut;
  GVariantBuilder builder;
  GVariant * message;
  va_list args;

  point_cut = gum_invocation_context_get_point_cut (context);
  g_variant_builder_init (&builder, G_VARIANT_TYPE (
      priv->data->send_arg_type_signature[point_cut - GUM_POINT_ENTER]));

  va_start (args, argument_index);

  while (argument_index != G_MAXUINT)
  {
    guint byte_array_length_argument_index = 0;
    gpointer argument_value;
    GumVariableType var_type;
    GVariant * value;

    var_type = va_arg (args, GumVariableType);
    if (var_type == GUM_VARIABLE_BYTE_ARRAY)
    {
      byte_array_length_argument_index = (argument_index & 0xffff) - 1;
      argument_index >>= 16;
    }

    if (argument_index == 0)
    {
      argument_value = gum_invocation_context_get_return_value (context);
    }
    else
    {
      argument_value = gum_invocation_context_get_nth_argument (context,
          argument_index - 1);
    }

    switch (var_type)
    {
      case GUM_VARIABLE_INT32:
        value = g_variant_new_int32 ((gint32)
            GPOINTER_TO_SIZE (argument_value));
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
              context, argument_index);
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
              context, argument_index);
        }

        value = g_variant_new_string (str_utf8);

        g_free (str_utf8);

        break;
      }

      case GUM_VARIABLE_BYTE_ARRAY:
      {
        gpointer byte_array_data = argument_value;
        gssize byte_array_length;
        gpointer byte_array_copy;

        byte_array_length = (gssize) GPOINTER_TO_SIZE (
            gum_invocation_context_get_nth_argument (context,
                byte_array_length_argument_index));

        byte_array_copy = g_memdup (byte_array_data, byte_array_length);

        value = g_variant_new_from_data (G_VARIANT_TYPE ("ay"),
            byte_array_copy, byte_array_length, TRUE, g_free, byte_array_copy);

        break;
      }

      case GUM_VARIABLE_GUID:
      {
        GumGuid * guid = (GumGuid *) argument_value;
        guint8 * p = (guint8 *) &guid->data4;
        gchar * guid_str;

        guid_str = g_strdup_printf (
            "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            guid->data1, guid->data2, guid->data3,
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

        value = g_variant_new_from_data (G_VARIANT_TYPE_STRING, guid_str, 39,
            TRUE, g_free, guid_str);

        break;
      }

      default:
        value = NULL;
        g_assert_not_reached ();
    }

    g_variant_builder_add_value (&builder, value);

    argument_index = va_arg (args, guint);
  }

  va_end (args);

  message = g_variant_ref_sink (g_variant_builder_end (&builder));
  priv->message_handler_func (self, message, priv->message_handler_data);
  g_variant_unref (message);
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

        width = (gint) GPOINTER_TO_SIZE (
            gum_invocation_context_get_nth_argument (context, arg_index + 0));
        precision = (gint) GPOINTER_TO_SIZE (
            gum_invocation_context_get_nth_argument (context, arg_index + 1));
        arg_index += 2;

        value = gum_consume_format_string_arg_value (&t, context, &arg_index,
            &temporary_storage);

        g_string_append_printf (str, temp_format, width, precision, value);
      }
      else if (t.width_in_argument || t.precision_in_argument)
      {
        gint width_or_precision;

        width_or_precision = (gint) GPOINTER_TO_SIZE (
            gum_invocation_context_get_nth_argument (context, arg_index + 0));
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
