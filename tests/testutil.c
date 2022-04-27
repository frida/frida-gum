/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#include "valgrind.h"
#ifdef HAVE_ANDROID
# include "backend-linux/gumandroid.h"
#endif
#ifdef HAVE_FREEBSD
# include "backend-freebsd/gumfreebsd.h"
#endif
#ifdef HAVE_QNX
# include "backend-qnx/gumqnx.h"
#endif

#if defined (HAVE_WINDOWS) && defined (_DEBUG)
# include <crtdbg.h>
#endif
#ifdef HAVE_WINDOWS
# include <excpt.h>
# define VC_EXTRALEAN
# include <windows.h>
#else
# include <setjmp.h>
# include <signal.h>
# ifdef HAVE_DARWIN
#  include <unistd.h>
#  include <mach-o/dyld.h>
#  include <sys/sysctl.h>
#  include <sys/types.h>
# else
#  include <stdio.h>
# endif
# if defined (HAVE_LINUX) || defined (HAVE_FREEBSD)
#  include <dlfcn.h>
# endif
#endif
#include <stdlib.h>
#include <string.h>

#define TESTCASE(NAME) \
    void test_testutil_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("TestUtil", test_testutil, NAME)

TESTLIST_BEGIN (testutil)
  TESTENTRY (line_diff)
  TESTENTRY (binary_diff)
  TESTENTRY (text_diff)
  TESTENTRY (xml_pretty_split)
  TESTENTRY (xml_multiline_diff_same_size)
TESTLIST_END ()

#ifndef HAVE_WINDOWS
static gchar * find_data_dir_from_executable_path (const gchar * path);
#endif

static gchar * byte_array_to_hex_string (const guint8 * bytes, guint length);
static gchar * byte_array_to_bin_string (const guint8 * bytes, guint length);
static gchar * prettify_xml (const gchar * input_xml);
static void on_start_element (GMarkupParseContext * context,
    const gchar * element_name, const gchar ** attribute_names,
    const gchar ** attribute_values, gpointer user_data,
    GError ** error);
static void on_end_element (GMarkupParseContext * context,
    const gchar * element_name, gpointer user_data, GError ** error);
static void on_text (GMarkupParseContext * context, const gchar * text,
    gsize text_len, gpointer user_data, GError ** error);
static gchar * diff_line (const gchar * expected_line,
    const gchar * actual_line);
static void append_indent (GString * str, guint indent_level);

TESTCASE (binary_diff)
{
  const guint8 expected_bytes[] = { 0x48, 0x8b, 0x40, 0x07 };
  const guint8 bad_bytes[] = { 0x4c, 0x8b, 0x40, 0x07 };
  const gchar * expected_diff =
      "In hex:\n"
      "-------\n"
      "\n"
      "48 8b 40 07  <-- Expected\n"
      " #\n"
      "4c 8b 40 07  <-- Wrong\n"
      "\n"
      "In binary:\n"
      "----------\n"
      "\n"
      "0100 1000  1000 1011  0100 0000  0000 0111  <-- Expected\n"
      "      #\n"
      "0100 1100  1000 1011  0100 0000  0000 0111  <-- Wrong\n";
  gchar * diff;

  diff = test_util_diff_binary (expected_bytes, sizeof (expected_bytes),
      bad_bytes, sizeof (bad_bytes));
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

TESTCASE (text_diff)
{
  const gchar * expected_text = "Badger\nSnake\nMushroom";
  const gchar * bad_text      = "Badger\nSnakE\nMushroom";
  const gchar * expected_diff = "Badger\n"
                                "\n"
                                "Snake  <-- Expected\n"
                                "    #\n"
                                "SnakE  <-- Wrong\n"
                                "\n"
                                "Mushroom\n";
  gchar * diff;

  diff = test_util_diff_text (expected_text, bad_text);
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

TESTCASE (xml_pretty_split)
{
  const gchar * input_xml = "<foo><bar id=\"2\">Woot</bar></foo>";
  const gchar * expected_xml =
      "<foo>\n"
      "  <bar id=\"2\">\n"
      "    Woot\n"
      "  </bar>\n"
      "</foo>\n";
  gchar * output_xml;

  output_xml = prettify_xml (input_xml);
  g_assert_cmpstr (output_xml, ==, expected_xml);
  g_free (output_xml);
}

TESTCASE (xml_multiline_diff_same_size)
{
  const gchar * expected_xml = "<foo><bar id=\"4\"></bar></foo>";
  const gchar * bad_xml      = "<foo><bar id=\"5\"></bar></foo>";
  const gchar * expected_diff = "<foo>\n"
                                "\n"
                                "  <bar id=\"4\">  <-- Expected\n"
                                "           #\n"
                                "  <bar id=\"5\">  <-- Wrong\n"
                                "\n"
                                "  </bar>\n"
                                "</foo>\n";
  gchar * diff;

  diff = test_util_diff_xml (expected_xml, bad_xml);
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

TESTCASE (line_diff)
{
  const gchar * expected_xml = "<tag/>";
  const gchar * bad_xml = "<taG/>";
  const gchar * expected_diff = "\n"
                                "<tag/>  <-- Expected\n"
                                "   #\n"
                                "<taG/>  <-- Wrong\n";
  gchar * diff;

  diff = diff_line (expected_xml, bad_xml);
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

/* Implementation */

static gboolean gum_test_assign_own_range_if_matching (
    const GumModuleDetails * details, gpointer user_data);

static GumMemoryRange _test_util_own_range = { 0, 0 };
static gchar * _test_util_system_module_name = NULL;
static GumHeapApiList * _test_util_heap_apis = NULL;

void
_test_util_init (void)
{
  gum_process_enumerate_modules (gum_test_assign_own_range_if_matching,
      &_test_util_own_range);
}

static gboolean
gum_test_assign_own_range_if_matching (const GumModuleDetails * details,
                                       gpointer user_data)
{
  if (GUM_MEMORY_RANGE_INCLUDES (details->range,
      GUM_ADDRESS (gum_test_assign_own_range_if_matching)))
  {
    GumMemoryRange * own_range = user_data;
    memcpy (own_range, details->range, sizeof (GumMemoryRange));
    return FALSE;
  }

  return TRUE;
}

void
_test_util_deinit (void)
{
  g_free (_test_util_system_module_name);
  _test_util_system_module_name = NULL;

  if (_test_util_heap_apis != NULL)
  {
    gum_heap_api_list_free (_test_util_heap_apis);
    _test_util_heap_apis = NULL;
  }
}

GumSampler *
heap_access_counter_new (void)
{
  return gum_call_count_sampler_new (malloc, calloc, realloc, free, NULL);
}

void
assert_basename_equals (const gchar * expected_filename,
                        const gchar * actual_filename)
{
  gchar * expected_basename, * actual_basename;

  expected_basename = g_path_get_basename (expected_filename);
  actual_basename = g_path_get_basename (actual_filename);

  g_assert_cmpstr (expected_basename, ==, actual_basename);

  g_free (expected_basename);
  g_free (actual_basename);
}

gchar *
test_util_diff_binary (const guint8 * expected_bytes,
                       guint expected_length,
                       const guint8 * actual_bytes,
                       guint actual_length)
{
  GString * full_diff;
  gchar * expected_str, * actual_str, * diff;

  full_diff = g_string_new ("In hex:\n");
  g_string_append (full_diff, "-------\n");
  expected_str = byte_array_to_hex_string (expected_bytes, expected_length);
  actual_str = byte_array_to_hex_string (actual_bytes, actual_length);
  diff = diff_line (expected_str, actual_str);
  g_string_append (full_diff, diff);
  g_free (diff);
  g_free (actual_str);
  g_free (expected_str);

  g_string_append_c (full_diff, '\n');

  g_string_append (full_diff, "In binary:\n");
  g_string_append (full_diff, "----------\n");
  expected_str = byte_array_to_bin_string (expected_bytes, expected_length);
  actual_str = byte_array_to_bin_string (actual_bytes, actual_length);
  diff = diff_line (expected_str, actual_str);
  g_string_append (full_diff, diff);
  g_free (diff);
  g_free (actual_str);
  g_free (expected_str);

  return g_string_free (full_diff, FALSE);
}

gchar *
test_util_diff_text (const gchar * expected_text,
                     const gchar * actual_text)
{
  GString * full_diff;
  gchar ** expected_lines, ** actual_lines;
  guint i;

  expected_lines = g_strsplit (expected_text, "\n", 0);
  actual_lines = g_strsplit (actual_text, "\n", 0);

  full_diff = g_string_sized_new (strlen (expected_text));

  for (i = 0; expected_lines[i] != NULL && actual_lines[i] != NULL; i++)
  {
    gchar * diff;

    if (expected_lines[i][0] == '\0' || actual_lines[i][0] == '\0')
      continue;

    diff = diff_line (expected_lines[i], actual_lines[i]);
    g_string_append (full_diff, diff);
    g_string_append_c (full_diff, '\n');
    g_free (diff);
  }

  g_strfreev (expected_lines);
  g_strfreev (actual_lines);

  return g_string_free (full_diff, FALSE);
}

gchar *
test_util_diff_xml (const gchar * expected_xml,
                    const gchar * actual_xml)
{
  gchar * expected_xml_pretty, * actual_xml_pretty, * diff;

  expected_xml_pretty = prettify_xml (expected_xml);
  actual_xml_pretty = prettify_xml (actual_xml);

  diff = test_util_diff_text (expected_xml_pretty, actual_xml_pretty);

  g_free (expected_xml_pretty);
  g_free (actual_xml_pretty);

  return diff;
}

gchar *
test_util_get_data_dir (void)
{
#if defined (HAVE_WINDOWS)
  g_assert_not_reached (); /* FIXME: once this is needed on Windows */
  return NULL;
#elif defined (HAVE_DARWIN)
  guint image_count, image_idx;

  image_count = _dyld_image_count ();
  for (image_idx = 0; image_idx != image_count; image_idx++)
  {
    const gchar * path = _dyld_get_image_name (image_idx);

    if (g_str_has_suffix (path, "/gum-tests"))
      return find_data_dir_from_executable_path (path);
  }

  return g_strdup ("/Library/Frida/tests/data");
#elif defined (HAVE_LINUX)
  gchar * result, * path;

  path = g_file_read_link ("/proc/self/exe", NULL);
  result = find_data_dir_from_executable_path (path);
  g_free (path);

  return result;
#elif defined (HAVE_FREEBSD)
  gchar * result, * path;

  path = gum_freebsd_query_program_path_for_self (NULL);
  result = find_data_dir_from_executable_path (path);
  g_free (path);

  return result;
#elif defined (HAVE_QNX)
  gchar * result, * path;

  path = gum_qnx_query_program_path_for_self (NULL);
  result = find_data_dir_from_executable_path (path);
  g_free (path);

  return result;
#else
# error Implement support for your OS here
#endif
}

#ifndef HAVE_WINDOWS

static gchar *
find_data_dir_from_executable_path (const gchar * path)
{
  gchar * result, * dir;

  dir = g_path_get_dirname (path);
  result = g_build_filename (dir, "data", NULL);
  g_free (dir);

  return result;
}

#endif

const gchar *
test_util_get_system_module_name (void)
{
#if defined (HAVE_WINDOWS)
  return "kernel32.dll";
#elif defined (HAVE_DARWIN)
  return "libSystem.B.dylib";
#elif defined (HAVE_ANDROID)
  return "libc.so";
#elif defined (HAVE_QNX)
  return "libbacktrace.so.1";
#else
  if (_test_util_system_module_name == NULL)
  {
    gpointer libc_open;
    Dl_info info;
    gchar * target, * libc_path;

    libc_open = dlsym (RTLD_DEFAULT, "fopen");
    g_assert_nonnull (libc_open);

    g_assert_true (dladdr (libc_open, &info) != 0);
    g_assert_nonnull (info.dli_fname);

    target = g_file_read_link (info.dli_fname, NULL);
    if (target != NULL)
    {
      gchar * libc_dir;

      libc_dir = g_path_get_dirname (info.dli_fname);

      libc_path = g_canonicalize_filename (target, libc_dir);

      g_free (libc_dir);
      g_free (target);
    }
    else
    {
      libc_path = g_strdup (info.dli_fname);
    }

    _test_util_system_module_name = g_path_get_basename (libc_path);

    g_free (libc_path);
  }

  return _test_util_system_module_name;
#endif
}

#ifdef HAVE_ANDROID

const gchar *
test_util_get_android_java_vm_module_name (void)
{
  return (gum_android_get_api_level () >= 21) ? "libart.so" : "libdvm.so";
}

#endif

const GumHeapApiList *
test_util_heap_apis (void)
{
  if (_test_util_heap_apis == NULL)
    _test_util_heap_apis = gum_process_find_heap_apis ();
  return _test_util_heap_apis;
}

#ifdef HAVE_WINDOWS

gboolean
gum_is_debugger_present (void)
{
  return IsDebuggerPresent ();
}

guint8
gum_try_read_and_write_at (guint8 * a,
                           guint i,
                           gboolean * exception_raised_on_read,
                           gboolean * exception_raised_on_write)
{
  guint8 dummy_value_to_trick_optimizer = 0;

  if (exception_raised_on_read != NULL)
    *exception_raised_on_read = FALSE;
  if (exception_raised_on_write != NULL)
    *exception_raised_on_write = FALSE;

  __try
  {
    dummy_value_to_trick_optimizer = a[i];
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    if (exception_raised_on_read != NULL)
      *exception_raised_on_read = TRUE;
  }

  __try
  {
    a[i] = 42;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    if (exception_raised_on_write != NULL)
      *exception_raised_on_write = TRUE;
  }

  return dummy_value_to_trick_optimizer;
}

#else

#ifdef HAVE_DARWIN
# define GUM_SETJMP(env) setjmp (env)
# define GUM_LONGJMP(env, val) longjmp (env, val)
  typedef jmp_buf gum_jmp_buf;
#else
# define GUM_SETJMP(env) sigsetjmp (env, 1)
# define GUM_LONGJMP(env, val) siglongjmp (env, val)
  typedef sigjmp_buf gum_jmp_buf;
#endif

gboolean
gum_is_debugger_present (void)
{
#ifdef HAVE_DARWIN
  int mib[4];
  struct kinfo_proc info;
  size_t size;

  info.kp_proc.p_flag = 0;
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = getpid ();

  size = sizeof (info);
  sysctl (mib, G_N_ELEMENTS (mib), &info, &size, NULL, 0);

  return (info.kp_proc.p_flag & P_TRACED) != 0;
#else
  /* FIXME */
  return FALSE;
#endif
}

static gum_jmp_buf gum_try_read_and_write_context;
static struct sigaction gum_test_old_sigsegv;
static struct sigaction gum_test_old_sigbus;

static gboolean gum_test_should_forward_signal_to (gpointer handler);

static void
gum_test_on_signal (int sig,
                    siginfo_t * siginfo,
                    void * context)
{
  struct sigaction * action;

  action = (sig == SIGSEGV) ? &gum_test_old_sigsegv : &gum_test_old_sigbus;
  if ((action->sa_flags & SA_SIGINFO) != 0)
  {
    if (gum_test_should_forward_signal_to (action->sa_sigaction))
      action->sa_sigaction (sig, siginfo, context);
  }
  else
  {
    if (gum_test_should_forward_signal_to (action->sa_handler))
      action->sa_handler (sig);
  }

  GUM_LONGJMP (gum_try_read_and_write_context, 1337);
}

static gboolean
gum_test_should_forward_signal_to (gpointer handler)
{
  if (handler == NULL)
    return FALSE;

  return GUM_MEMORY_RANGE_INCLUDES (&_test_util_own_range,
      GUM_ADDRESS (handler));
}

guint8
gum_try_read_and_write_at (guint8 * a,
                           guint i,
                           gboolean * exception_raised_on_read,
                           gboolean * exception_raised_on_write)
{
  struct sigaction action;
  guint8 dummy_value_to_trick_optimizer = 0;
  GumExceptor * exceptor;

  if (exception_raised_on_read != NULL)
    *exception_raised_on_read = FALSE;
  if (exception_raised_on_write != NULL)
    *exception_raised_on_write = FALSE;

  exceptor = gum_exceptor_obtain ();

  action.sa_sigaction = gum_test_on_signal;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_SIGINFO;
  sigaction (SIGSEGV, &action, &gum_test_old_sigsegv);
  sigaction (SIGBUS, &action, &gum_test_old_sigbus);

#ifdef HAVE_ANDROID
  /* Work-around for Bionic bug up to and including Android L */
  sigset_t mask;

  sigprocmask (SIG_SETMASK, NULL, &mask);
#endif

  if (GUM_SETJMP (gum_try_read_and_write_context) == 0)
  {
    dummy_value_to_trick_optimizer = a[i];
  }
  else
  {
    if (exception_raised_on_read != NULL)
      *exception_raised_on_read = TRUE;

#ifdef HAVE_DARWIN
    /*
     * The Darwin Exceptor backend will currently disengage on an unhandled
     * exception. This is because guarded Mach ports may make it impossible
     * to forward to the previous handler. We may potentially improve on
     * this by detecting that the process has guarded ports.
     */
    gum_exceptor_reset (exceptor);
#endif
  }

#ifdef HAVE_ANDROID
  sigprocmask (SIG_SETMASK, &mask, NULL);
#endif

  if (GUM_SETJMP (gum_try_read_and_write_context) == 0)
  {
    a[i] = 42;
  }
  else
  {
    if (exception_raised_on_write != NULL)
      *exception_raised_on_write = TRUE;

#ifdef HAVE_DARWIN
    gum_exceptor_reset (exceptor);
#endif
  }

#ifdef HAVE_ANDROID
  sigprocmask (SIG_SETMASK, &mask, NULL);
#endif

  sigaction (SIGSEGV, &gum_test_old_sigsegv, NULL);
  memset (&gum_test_old_sigsegv, 0, sizeof (gum_test_old_sigsegv));
  sigaction (SIGBUS, &gum_test_old_sigbus, NULL);
  memset (&gum_test_old_sigbus, 0, sizeof (gum_test_old_sigbus));

  g_object_unref (exceptor);

  return dummy_value_to_trick_optimizer;
}

#endif

static gchar *
byte_array_to_hex_string (const guint8 * bytes,
                          guint length)
{
  GString * result;
  guint byte_idx;

  result = g_string_sized_new (length * 2 + length - 1);

  for (byte_idx = 0; byte_idx != length; byte_idx++)
  {
    if (byte_idx != 0)
      g_string_append_c (result, ' ');
    g_string_append_printf (result, "%02x", bytes[byte_idx]);
  }

  return g_string_free (result, FALSE);
}

static gchar *
byte_array_to_bin_string (const guint8 * bytes,
                          guint length)
{
  GString * result;
  guint byte_idx;

  result = g_string_sized_new (length * 9 + length * 2 - 2);

  for (byte_idx = 0; byte_idx != length; byte_idx++)
  {
    guint bit_idx;

    if (byte_idx != 0)
      g_string_append (result, "  ");

    for (bit_idx = 0; bit_idx != 8; bit_idx++)
    {
      gboolean bit_is_set;

      bit_is_set = (bytes[byte_idx] >> (7 - bit_idx)) & 1;

      if (bit_idx == 4)
        g_string_append_c (result, ' ');
      g_string_append_c (result, bit_is_set ? '1' : '0');
    }
  }

  return g_string_free (result, FALSE);
}

typedef struct _PrettifyState PrettifyState;

struct _PrettifyState
{
  GString * output_xml;
  guint indentation_level;
};

static gchar *
prettify_xml (const gchar * input_xml)
{
  PrettifyState state;
  GMarkupParser parser = { NULL, };
  GMarkupParseContext * context;

  state.output_xml = g_string_sized_new (80);
  state.indentation_level = 0;

  parser.start_element = on_start_element;
  parser.end_element = on_end_element;
  parser.text = on_text;

  context = g_markup_parse_context_new (&parser, 0, &state, NULL);
  g_markup_parse_context_parse (context, input_xml, strlen (input_xml), NULL);
  g_markup_parse_context_free (context);

  return g_string_free (state.output_xml, FALSE);
}

static void
on_start_element (GMarkupParseContext * context,
                  const gchar * element_name,
                  const gchar ** attribute_names,
                  const gchar ** attribute_values,
                  gpointer user_data,
                  GError ** error)
{
  PrettifyState * state = user_data;
  guint i;

  append_indent (state->output_xml, state->indentation_level);
  g_string_append_printf (state->output_xml, "<%s", element_name);

  for (i = 0; attribute_names[i] != NULL; i++)
  {
    g_string_append_printf (state->output_xml, " %s=\"%s\"",
        attribute_names[i], attribute_values[i]);
  }

  g_string_append (state->output_xml, ">\n");

  state->indentation_level++;
}

static void
on_end_element (GMarkupParseContext * context,
                const gchar * element_name,
                gpointer user_data,
                GError ** error)
{
  PrettifyState * state = user_data;

  state->indentation_level--;

  append_indent (state->output_xml, state->indentation_level);
  g_string_append_printf (state->output_xml, "</%s>\n", element_name);
}

static void
on_text (GMarkupParseContext * context,
         const gchar * text,
         gsize text_len,
         gpointer user_data,
         GError ** error)
{
  PrettifyState * state = user_data;

  if (text_len > 0)
  {
    append_indent (state->output_xml, state->indentation_level);
    g_string_append_len (state->output_xml, text, text_len);
    g_string_append_printf (state->output_xml, "\n");
  }
}

static gchar *
diff_line (const gchar * expected_line,
           const gchar * actual_line)
{
  GString * diff_str;
  guint diff_pos = 0;
  const gchar * expected = expected_line;
  const gchar * actual   = actual_line;

  if (strcmp (expected_line, actual_line) == 0)
    return g_strdup (actual_line);

  while (*expected != '\0' && *actual != '\0')
  {
    if (*expected != *actual)
    {
      diff_pos = expected - expected_line;
      break;
    }

    expected++;
    actual++;
  }

  diff_str = g_string_sized_new (80);
  g_string_append_c (diff_str, '\n');
  g_string_append_printf (diff_str, "%s  <-- Expected\n", expected_line);
  g_string_append_printf (diff_str, "%*s#\n", diff_pos, "");
  g_string_append_printf (diff_str, "%s  <-- Wrong\n", actual_line);

  return g_string_free (diff_str, FALSE);
}

static void
append_indent (GString * str,
               guint indent_level)
{
  guint i;

  for (i = 0; i < indent_level; i++)
    g_string_append (str, "  ");
}
