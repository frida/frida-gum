/*
 * Copyright (C) 2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <capstone/capstone.h>

#include "testutil.h"

#define TESTCASE(NAME) \
    void test_capstone_ ## NAME ( \
        TestCapstoneFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Core/Capstone", test_capstone, NAME, \
        TestCapstoneFixture)

#if defined (HAVE_I386)
# define DECODE(c) \
    g_assert_true (test_capstone_fixture_try_decode (fixture, c, sizeof (c)))
#elif defined (HAVE_ARM)
# define DECODE(raw_insn) \
    G_STMT_START \
    { \
      const guint16 value = raw_insn; \
      gconstpointer code = (gconstpointer) &value; \
      const gsize size = sizeof (value); \
      \
      g_assert_true (test_capstone_fixture_try_decode (fixture, code, size)); \
    } \
    G_STMT_END
# define DECODE_T2(a, b) \
    G_STMT_START \
    { \
      const guint16 value[2] = { a, b }; \
      gconstpointer code = (gconstpointer) &value; \
      const gsize size = sizeof (value); \
      \
      g_assert_true (test_capstone_fixture_try_decode (fixture, code, size)); \
    } \
    G_STMT_END
#elif defined (HAVE_ARM64)
# define DECODE(raw_insn) \
    G_STMT_START \
    { \
      const guint32 value = raw_insn; \
      gconstpointer code = (gconstpointer) &value; \
      const gsize size = sizeof (value); \
      \
      g_assert_true (test_capstone_fixture_try_decode (fixture, code, size)); \
    } \
    G_STMT_END
#endif
#define EXPECT(expected_id, expected_description) \
    g_assert_cmpuint (fixture->insn->id, ==, expected_id); \
    g_assert_cmpstr (fixture->description, ==, expected_description)

typedef struct _TestCapstoneFixture TestCapstoneFixture;

struct _TestCapstoneFixture
{
  csh handle;
  cs_insn * insn;
  gchar * description;
};

static void
test_capstone_fixture_setup (TestCapstoneFixture * fixture,
                             gconstpointer data)
{
  cs_err err;

  err = cs_open (GUM_DEFAULT_CS_ARCH,
#ifdef HAVE_ARM
      CS_MODE_THUMB,
#else
      GUM_DEFAULT_CS_MODE,
#endif
      &fixture->handle);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  err = cs_option (fixture->handle, CS_OPT_DETAIL, CS_OPT_ON);
  g_assert_cmpint (err, ==, CS_ERR_OK);

  fixture->insn = NULL;
  fixture->description = NULL;
}

static void
test_capstone_fixture_teardown (TestCapstoneFixture * fixture,
                                gconstpointer data)
{
  g_free (fixture->description);

  if (fixture->insn != NULL)
    cs_free (fixture->insn, 1);

  cs_close (&fixture->handle);
}

static gboolean
test_capstone_fixture_try_decode (TestCapstoneFixture * fixture,
                                  gconstpointer code,
                                  gsize size)
{
  gboolean success;

  g_free (fixture->description);
  fixture->description = NULL;

  if (fixture->insn != NULL)
  {
    cs_free (fixture->insn, 1);
    fixture->insn = NULL;
  }

  success =
      cs_disasm (fixture->handle, code, size, 0x1000, 0, &fixture->insn) == 1;

  if (success)
  {
    cs_insn * insn = fixture->insn;

    fixture->description = g_strconcat (
        insn->mnemonic,
        (insn->op_str[0] != '\0') ? " " : "",
        insn->op_str,
        NULL);
  }

  return success;
}
