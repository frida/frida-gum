/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "testutil.h"

#include "gumcodewriter.h"

#include <string.h>

#define CODE_WRITER_TESTCASE(NAME) \
    void test_code_writer_ ## NAME ( \
        TestCodeWriterFixture * fixture, gconstpointer data)
#define CODE_WRITER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE (CodeWriter, test_code_writer, NAME, \
        TestCodeWriterFixture)

typedef struct _TestCodeWriterFixture
{
  guint8 output[32];
  GumCodeWriter cw;
} TestCodeWriterFixture;

static void
test_code_writer_fixture_setup (TestCodeWriterFixture * fixture,
                                gconstpointer data)
{
  gum_code_writer_init (&fixture->cw, fixture->output);
}

static void
test_code_writer_fixture_teardown (TestCodeWriterFixture * fixture,
                                   gconstpointer data)
{
  gum_code_writer_free (&fixture->cw);
}

TEST_LIST_BEGIN (codewriter)
  CODE_WRITER_TESTENTRY (jump_label)
  CODE_WRITER_TESTENTRY (call_label)
  CODE_WRITER_TESTENTRY (flush_on_free)
TEST_LIST_END ()

CODE_WRITER_TESTCASE (jump_label)
{
  const guint8 expected_code[] = {
  /* start: */
    0x81, 0xf9, 0x39, 0x05, 0x00, 0x00, /* cmp ecx, 1337        */
    0x2e, 0x74, 0x05,                   /* hnt je handle_error  */
    0x2e, 0x7e, 0x02,                   /* hnt jle handle_error */
    0xeb, 0x01,                         /* jmp beach            */
  /* handle_error: */
    0xcc,                               /* int 3                */
  /* beach: */
    0x90,                               /* nop                  */
    0xeb, 0xee                          /* jmp start            */
  };
  const gchar * start_lbl = "start";
  const gchar * handle_error_lbl = "handle_error";
  const gchar * beach_lbl = "beach";

  gum_code_writer_put_label (&fixture->cw, start_lbl);
  gum_code_writer_put_cmp_reg_i32 (&fixture->cw, GUM_REG_ECX, 1337);
  gum_code_writer_put_jz_label (&fixture->cw, handle_error_lbl, GUM_UNLIKELY);
  gum_code_writer_put_jle_label (&fixture->cw, handle_error_lbl, GUM_UNLIKELY);
  gum_code_writer_put_jmp_short_label (&fixture->cw, beach_lbl);

  gum_code_writer_put_label (&fixture->cw, handle_error_lbl);
  gum_code_writer_put_int3 (&fixture->cw);

  gum_code_writer_put_label (&fixture->cw, beach_lbl);
  gum_code_writer_put_nop (&fixture->cw);
  gum_code_writer_put_jmp_short_label (&fixture->cw, start_lbl);

  gum_code_writer_flush (&fixture->cw);

  g_assert_cmpuint (gum_code_writer_offset (&fixture->cw), ==,
      sizeof (expected_code));
  g_assert_cmpint (
      memcmp (fixture->output, expected_code, sizeof (expected_code)), ==, 0);
}

CODE_WRITER_TESTCASE (call_label)
{
  const guint8 expected_code[] = {
    0xe8, 0x01, 0x00, 0x00, 0x00, /* call func */
    0xc3,                         /* retn      */
  /* func: */
    0xc3                          /* retn      */
  };
  const gchar * func_lbl = "func";

  gum_code_writer_put_call_near_label (&fixture->cw, func_lbl);
  gum_code_writer_put_ret (&fixture->cw);

  gum_code_writer_put_label (&fixture->cw, func_lbl);
  gum_code_writer_put_ret (&fixture->cw);

  gum_code_writer_flush (&fixture->cw);

  g_assert_cmpuint (gum_code_writer_offset (&fixture->cw), ==,
      sizeof (expected_code));
  g_assert_cmpint (
      memcmp (fixture->output, expected_code, sizeof (expected_code)), ==, 0);
}

CODE_WRITER_TESTCASE (flush_on_free)
{
  const guint8 expected_code[] = {
    0xe8, 0x00, 0x00, 0x00, 0x00, /* call func */
    0xc3                          /* retn      */
  };
  GumCodeWriter cw;
  const gchar * func_lbl = "func";

  gum_code_writer_init (&cw, fixture->output);

  gum_code_writer_put_call_near_label (&cw, func_lbl);
  gum_code_writer_put_label (&cw, func_lbl);
  gum_code_writer_put_ret (&cw);

  gum_code_writer_free (&cw);

  g_assert_cmpint (
      memcmp (fixture->output, expected_code, sizeof (expected_code)), ==, 0);
}

