/*
 * Copyright (C) 2010-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "script-fixture.c"

TEST_LIST_BEGIN (script)
  SCRIPT_TESTENTRY (invalid_script_should_return_null)
  SCRIPT_TESTENTRY (message_can_be_sent)
  SCRIPT_TESTENTRY (message_can_be_received)
  SCRIPT_TESTENTRY (recv_may_specify_desired_message_type)
  SCRIPT_TESTENTRY (recv_can_be_waited_for)
  SCRIPT_TESTENTRY (argument_can_be_read)
  SCRIPT_TESTENTRY (argument_can_be_replaced)
  SCRIPT_TESTENTRY (return_value_can_be_read)
  SCRIPT_TESTENTRY (sword_can_be_read)
  SCRIPT_TESTENTRY (uword_can_be_read)
  SCRIPT_TESTENTRY (s8_can_be_read)
  SCRIPT_TESTENTRY (u8_can_be_read)
  SCRIPT_TESTENTRY (s16_can_be_read)
  SCRIPT_TESTENTRY (u16_can_be_read)
  SCRIPT_TESTENTRY (s32_can_be_read)
  SCRIPT_TESTENTRY (u32_can_be_read)
  SCRIPT_TESTENTRY (s64_can_be_read)
  SCRIPT_TESTENTRY (u64_can_be_read)
  SCRIPT_TESTENTRY (utf8_string_can_be_read)
  SCRIPT_TESTENTRY (utf8_string_can_be_allocated)
  SCRIPT_TESTENTRY (utf16_string_can_be_read)
  SCRIPT_TESTENTRY (utf16_string_can_be_allocated)
#ifdef G_OS_WIN32
  SCRIPT_TESTENTRY (ansi_string_can_be_read)
  SCRIPT_TESTENTRY (ansi_string_can_be_allocated)
#endif
  SCRIPT_TESTENTRY (invalid_read_results_in_exception)
  SCRIPT_TESTENTRY (can_resolve_export_by_name)
TEST_LIST_END ()

SCRIPT_TESTCASE (can_resolve_export_by_name)
{
#ifdef G_OS_WIN32
  HMODULE mod;
  gpointer actual_address;
  char actual_address_str[64];

  mod = GetModuleHandle (_T ("ws2_32.dll"));
  g_assert (mod != NULL);
  actual_address = GetProcAddress (mod, "recv");
  g_assert (actual_address != NULL);
  sprintf_s (actual_address_str, sizeof (actual_address_str),
      "%" G_GSIZE_MODIFIER "d", GPOINTER_TO_SIZE (actual_address));

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.findModuleExportByName('ws2_32.dll', 'recv'));");
  EXPECT_SEND_MESSAGE_WITH (actual_address_str);
#endif
}

SCRIPT_TESTCASE (invalid_script_should_return_null)
{
  GError * err = NULL;

  g_assert (gum_script_from_string ("'", NULL) == NULL);

  g_assert (gum_script_from_string ("'", &err) == NULL);
  g_assert (err != NULL);
  g_assert_cmpstr (err->message, ==,
      "Script(line 1): SyntaxError: Unexpected token ILLEGAL");
}

SCRIPT_TESTCASE (message_can_be_sent)
{
  COMPILE_AND_LOAD_SCRIPT ("send(1234);");
  EXPECT_SEND_MESSAGE_WITH ("1234");
}

SCRIPT_TESTCASE (message_can_be_received)
{
  COMPILE_AND_LOAD_SCRIPT (
      "recv(function(message) {"
      "  if (message.type == 'ping')"
      "    send('pong');"
      "});");
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"ping\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"pong\"");
}

SCRIPT_TESTCASE (recv_may_specify_desired_message_type)
{
  COMPILE_AND_LOAD_SCRIPT (
      "recv('wobble', function(message) {"
      "  send('wibble');"
      "});"
      "recv('ping', function(message) {"
      "  send('pong');"
      "});");
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"ping\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"pong\"");
}

typedef struct _GumInvokeTargetContext GumInvokeTargetContext;

struct _GumInvokeTargetContext
{
  GumScript * script;
  volatile gboolean started;
  volatile gboolean finished;
};

SCRIPT_TESTCASE (recv_can_be_waited_for)
{
  GThread * worker_thread;
  GumInvokeTargetContext ctx;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_FORMAT ", {"
      "  onEnter: function(args) {"
      "    op = recv('poke', function(pokeMessage) {"
      "      send('pokeBack');"
      "    });"
      "    op.wait();"
      "    send('pokeReceived');"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();

  ctx.script = fixture->script;
  ctx.started = FALSE;
  ctx.finished = FALSE;
  worker_thread = g_thread_create (invoke_target_function_int_worker,
      &ctx, TRUE, NULL);
  while (!ctx.started)
    g_usleep (G_USEC_PER_SEC / 200);

  g_usleep (G_USEC_PER_SEC / 25);
  EXPECT_NO_MESSAGES ();
  g_assert (!ctx.finished);

  POST_MESSAGE ("{\"type\":\"poke\"}");
  g_thread_join (worker_thread);
  g_assert (ctx.finished);
  EXPECT_SEND_MESSAGE_WITH ("\"pokeBack\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeReceived\"");
  EXPECT_NO_MESSAGES ();
}

static gpointer
invoke_target_function_int_worker (gpointer data)
{
  GumInvokeTargetContext * ctx = (GumInvokeTargetContext *) data;

  ctx->started = TRUE;
  target_function_int (42);
  ctx->finished = TRUE;

  return NULL;
}

SCRIPT_TESTCASE (argument_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_FORMAT ", {"
      "  onEnter: function(args) {"
      "    send(args[0]);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("42");
}

SCRIPT_TESTCASE (argument_can_be_replaced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var replacementString = Memory.allocUtf8String('Hei');"
      "Interceptor.attach(" GUM_PTR_FORMAT ", {"
      "  onEnter: function(args) {"
      "    args[0] = replacementString;"
      "  }"
      "});", target_function_string);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpstr (target_function_string ("Hello"), ==, "Hei");
  EXPECT_NO_MESSAGES ();
}

SCRIPT_TESTCASE (return_value_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_FORMAT ", {"
      "  onLeave: function(retval) {"
      "    send(retval);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("315");
}

SCRIPT_TESTCASE (sword_can_be_read)
{
  int val = -1337000;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readSWord(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-1337000");
}

SCRIPT_TESTCASE (uword_can_be_read)
{
  unsigned int val = 1337000;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUWord(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("1337000");
}

SCRIPT_TESTCASE (s8_can_be_read)
{
  gint8 val = -42;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS8(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-42");
}

SCRIPT_TESTCASE (u8_can_be_read)
{
  guint8 val = 42;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU8(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("42");
}

SCRIPT_TESTCASE (s16_can_be_read)
{
  gint16 val = -12123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS16(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-12123");
}

SCRIPT_TESTCASE (u16_can_be_read)
{
  guint16 val = 12123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU16(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("12123");
}

SCRIPT_TESTCASE (s32_can_be_read)
{
  gint32 val = -120123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS32(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-120123");
}

SCRIPT_TESTCASE (u32_can_be_read)
{
  guint32 val = 120123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU32(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("120123");
}

SCRIPT_TESTCASE (s64_can_be_read)
{
  gint64 val = G_GINT64_CONSTANT (-1201239876783);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS64(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-1201239876783");
}

SCRIPT_TESTCASE (u64_can_be_read)
{
  guint64 val = G_GUINT64_CONSTANT (1201239876783);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU64(" GUM_PTR_FORMAT "));", &val);
  EXPECT_SEND_MESSAGE_WITH ("1201239876783");
}

SCRIPT_TESTCASE (utf8_string_can_be_read)
{
  const gchar * str = "Bjørheimsbygd";
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(" GUM_PTR_FORMAT "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

SCRIPT_TESTCASE (utf8_string_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.readUtf8String(Memory.allocUtf8String('Bjørheimsbygd')));");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

SCRIPT_TESTCASE (utf16_string_can_be_read)
{
  const gchar * str_utf8 = "Bjørheimsbygd";
  gunichar2 * str = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(" GUM_PTR_FORMAT "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
  g_free (str);
}

SCRIPT_TESTCASE (utf16_string_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String("
      "Memory.allocUtf16String('Bjørheimsbygd')));");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

#ifdef G_OS_WIN32

SCRIPT_TESTCASE (ansi_string_can_be_read)
{
  const gchar * str_utf8 = "Bjørheimsbygd";
  gunichar2 * str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  gchar str[64];
  WideCharToMultiByte (CP_THREAD_ACP, 0, (LPCWSTR) str_utf16, -1,
      (LPSTR) str, sizeof (str), NULL, NULL);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readAnsiString(" GUM_PTR_FORMAT "));",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
  g_free (str_utf16);
}

SCRIPT_TESTCASE (ansi_string_can_be_allocated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Memory.readAnsiString(Memory.allocAnsiString('Bjørheimsbygd')));");
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

#endif

SCRIPT_TESTCASE (invalid_read_results_in_exception)
{
  const gchar * type_name[] = {
      "SWord",
      "UWord",
      "S8",
      "U8",
      "S16",
      "U16",
      "S32",
      "U32",
      "S64",
      "U64",
      "Utf8String",
      "Utf16String",
#ifdef G_OS_WIN32
      "AnsiString"
#endif
  };
  guint i;

  for (i = 0; i != G_N_ELEMENTS (type_name); i++)
  {
    gchar * source;

    source = g_strconcat ("Memory.read", type_name[i], "(1336);", NULL);
    COMPILE_AND_LOAD_SCRIPT (source);
    EXPECT_ERROR_MESSAGE_WITH (1, "Error: access violation reading 0x538");
    g_free (source);
  }
}

GUM_NOINLINE static int
target_function_int (int arg)
{
  int result = 0;
  int i;

  for (i = 0; i != 10; i++)
    result += i * arg;

  return result;
}

GUM_NOINLINE static const gchar *
target_function_string (const gchar * arg)
{
  int i;

  for (i = 0; i != 10; i++)
    gum_dummy_global_to_trick_optimizer += i * arg[0];

  return arg;
}
