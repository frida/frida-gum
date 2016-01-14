/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 * Copyright (C) 2009 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __TEST_UTIL_H__
#define __TEST_UTIL_H__

#include <gum/gum.h>
#include <gum/gum-heap.h>
#include <gum/gum-prof.h>

#define TEST_LIST_BEGIN(NAME) \
  void test_ ##NAME## _add_tests (gpointer fixture_data) \
  {
#define TEST_LIST_END() \
  }

#define TEST_ENTRY_SIMPLE(NAME, PREFIX, FUNC)                             \
  G_STMT_START                                                            \
  {                                                                       \
    extern void PREFIX## _ ##FUNC (void);                                 \
    g_test_add_func ("/" NAME "/" #FUNC, PREFIX## _ ##FUNC);              \
  }                                                                       \
  G_STMT_END;
#define TEST_ENTRY_WITH_FIXTURE(NAME, PREFIX, FUNC, STRUCT)               \
  G_STMT_START                                                            \
  {                                                                       \
    extern void PREFIX## _ ##FUNC (STRUCT * fixture, gconstpointer data); \
    g_test_add ("/" NAME "/" #FUNC,                                       \
        STRUCT,                                                           \
        fixture_data,                                                     \
        PREFIX## _fixture_setup,                                          \
        PREFIX## _ ##FUNC,                                                \
        PREFIX## _fixture_teardown);                                      \
  }                                                                       \
  G_STMT_END;

#define TEST_RUN_LIST(NAME) TEST_RUN_LIST_WITH_DATA (NAME, NULL)
#define TEST_RUN_LIST_WITH_DATA(NAME, FIXTURE_DATA)                       \
  G_STMT_START                                                            \
  {                                                                       \
    extern void test_ ##NAME## _add_tests (gpointer fixture_data);        \
    test_ ##NAME## _add_tests (FIXTURE_DATA);                             \
  }                                                                       \
  G_STMT_END

#define GUM_ASSERT_CMPADDR(n1, cmp, n2) \
    g_assert_cmphex (GPOINTER_TO_SIZE (n1), cmp, GPOINTER_TO_SIZE (n2))

#ifdef G_OS_WIN32
# define GUM_TESTS_MODULE_NAME "gum-tests.exe"
#else
# define GUM_TESTS_MODULE_NAME "gum-tests"
#endif
#define SYSTEM_MODULE_NAME test_util_get_system_module_name ()
#if defined (G_OS_WIN32)
# define SYSTEM_MODULE_EXPORT "Sleep"
#elif defined (HAVE_QNX)
# define SYSTEM_MODULE_EXPORT "bt_get_backtrace"
#else
# define SYSTEM_MODULE_EXPORT "sendto"
#endif

G_BEGIN_DECLS

G_GNUC_INTERNAL void _test_util_init (void);
G_GNUC_INTERNAL void _test_util_deinit (void);

GumSampler * heap_access_counter_new (void);

void assert_basename_equals (const gchar * expected_filename,
    const gchar * actual_filename);

gchar * test_util_diff_binary (const guint8 * expected_bytes,
    guint expected_length, const guint8 * actual_bytes,
    guint actual_length);
gchar * test_util_diff_text (const gchar * expected_text,
    const gchar * actual_text);
gchar * test_util_diff_xml (const gchar * expected_xml,
    const gchar * actual_xml);

gchar * test_util_get_data_dir (void);
const gchar * test_util_get_system_module_name (void);

const GumHeapApiList * test_util_heap_apis (void);

gboolean gum_is_debugger_present (void);
guint8 gum_try_read_and_write_at (guint8 * a, guint i,
    gboolean * exception_raised_on_read, gboolean * exception_raised_on_write);

G_END_DECLS

#endif
