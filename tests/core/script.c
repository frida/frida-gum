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
  SCRIPT_TESTENTRY (argument_can_be_sent)
  SCRIPT_TESTENTRY (return_value_can_be_sent)
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
  SCRIPT_TESTENTRY (utf16_string_can_be_read)
TEST_LIST_END ()

SCRIPT_TESTCASE (invalid_script_should_return_null)
{
  GError * err = NULL;

  g_assert (gum_script_from_string ("'", NULL) == NULL);

  g_assert (gum_script_from_string ("'", &err) == NULL);
  g_assert (err != NULL);
  g_assert_cmpstr (err->message, ==,
      "Script(line 1): SyntaxError: Unexpected token ILLEGAL");
}

SCRIPT_TESTCASE (argument_can_be_sent)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(0x%x, {"
      "  onEnter: function(args) {"
      "    send(args[0]);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("42");
}

SCRIPT_TESTCASE (return_value_can_be_sent)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(0x%x, {"
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
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readSWord(0x%x));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-1337000");
}

SCRIPT_TESTCASE (uword_can_be_read)
{
  unsigned int val = 1337000;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUWord(0x%x));", &val);
  EXPECT_SEND_MESSAGE_WITH ("1337000");
}

SCRIPT_TESTCASE (s8_can_be_read)
{
  gint8 val = -42;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS8(0x%x));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-42");
}

SCRIPT_TESTCASE (u8_can_be_read)
{
  guint8 val = 42;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU8(0x%x));", &val);
  EXPECT_SEND_MESSAGE_WITH ("42");
}

SCRIPT_TESTCASE (s16_can_be_read)
{
  gint16 val = -12123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS16(0x%x));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-12123");
}

SCRIPT_TESTCASE (u16_can_be_read)
{
  guint16 val = 12123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU16(0x%x));", &val);
  EXPECT_SEND_MESSAGE_WITH ("12123");
}

SCRIPT_TESTCASE (s32_can_be_read)
{
  gint32 val = -120123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS32(0x%x));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-120123");
}

SCRIPT_TESTCASE (u32_can_be_read)
{
  guint32 val = 120123;
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU32(0x%x));", &val);
  EXPECT_SEND_MESSAGE_WITH ("120123");
}

SCRIPT_TESTCASE (s64_can_be_read)
{
  gint64 val = G_GINT64_CONSTANT (-1201239876783);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readS64(0x%x));", &val);
  EXPECT_SEND_MESSAGE_WITH ("-1201239876783");
}

SCRIPT_TESTCASE (u64_can_be_read)
{
  guint64 val = G_GUINT64_CONSTANT (1201239876783);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readU64(0x%x));", &val);
  EXPECT_SEND_MESSAGE_WITH ("1201239876783");
}

SCRIPT_TESTCASE (utf8_string_can_be_read)
{
  const gchar * str = "Bjørheimsbygd";
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf8String(0x%x));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
}

SCRIPT_TESTCASE (utf16_string_can_be_read)
{
  const gchar * str_utf8 = "Bjørheimsbygd";
  gunichar2 * str = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);
  COMPILE_AND_LOAD_SCRIPT ("send(Memory.readUtf16String(0x%x));", str);
  EXPECT_SEND_MESSAGE_WITH ("\"Bjørheimsbygd\"");
  g_free (str);
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