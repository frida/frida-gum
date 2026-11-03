/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#ifdef HAVE_WINDOWS
# include <windows.h>
#endif
#include <string.h>

#define TESTCASE(NAME) \
    void test_pe_module_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/PeModule", test_pe_module, NAME)

#define GUM_TEST_IMAGE_SIZE 0x1000
#define GUM_TEST_NT_OFFSET 0x40
#define GUM_TEST_PDATA_RVA 0x400
#define GUM_TEST_XDATA_RVA 0x800

#define GUM_TEST_XDATA(index) (GUM_TEST_XDATA_RVA + ((index) * 4))

#define GUM_TEST_ARM64_XDATA_HEADER(single_epilog, epilog_count, code_words) \
    (((single_epilog) << 21) | ((epilog_count) << 22) | ((code_words) << 27))
#define GUM_TEST_ARM64_END 0xe4
#define GUM_TEST_ARM64_END_C 0xe5
#define GUM_TEST_ARM_XDATA_FRAGMENT (1U << 22)

TESTLIST_BEGIN (pe_module)
  TESTENTRY (amd64_function_starts_skip_chained_entries)
  TESTENTRY (arm64_function_starts_skip_fragments)
  TESTENTRY (arm_function_starts_skip_fragments)
#if defined (HAVE_WINDOWS) && GLIB_SIZEOF_VOID_P == 8
  TESTENTRY (function_starts_include_system_exports)
#endif
TESTLIST_END ()

#if defined (HAVE_WINDOWS) && GLIB_SIZEOF_VOID_P == 8
typedef struct _GumTestExportCheckContext GumTestExportCheckContext;

struct _GumTestExportCheckContext
{
  GumAddress base;
  GHashTable * starts;
  guint num_checked;
};
#endif

static GumPeModule * gum_test_make_pe_module (GumPeMachine machine,
    const guint32 * pdata, gsize pdata_size, const guint32 * xdata,
    gsize xdata_size);
static GArray * gum_test_collect_function_starts (GumPeModule * module);
static gboolean gum_test_collect_function_start (GumAddress rva,
    gpointer user_data);
static void gum_test_assert_function_starts (GArray * starts,
    const guint32 * expected, guint n);
#if defined (HAVE_WINDOWS) && GLIB_SIZEOF_VOID_P == 8
static guint gum_test_check_exports_are_function_starts (
    const gchar * module_name);
static gboolean gum_test_check_export_is_function_start (
    const GumPeExportDetails * details, gpointer user_data);
#endif

TESTCASE (amd64_function_starts_skip_chained_entries)
{
  const guint32 pdata[] = {
    0x1000, 0x1010, GUM_TEST_XDATA (0),
    0x1010, 0x1020, GUM_TEST_XDATA (1),
    0x1020, 0x1030, GUM_TEST_PDATA_RVA | 1,
    0x1030, 0x1040, GUM_TEST_XDATA (0),
  };
  const guint32 xdata[] = {
    0x01,
    0x01 | (0x4 << 3),
  };
  const guint32 expected[] = { 0x1000, 0x1030 };
  GumPeModule * module;
  GArray * starts;

  module = gum_test_make_pe_module (GUM_PE_MACHINE_AMD64, pdata, sizeof (pdata),
      xdata, sizeof (xdata));
  starts = gum_test_collect_function_starts (module);

  gum_test_assert_function_starts (starts, expected, G_N_ELEMENTS (expected));

  g_array_unref (starts);
  g_object_unref (module);
}

TESTCASE (arm64_function_starts_skip_fragments)
{
  const guint32 pdata[] = {
    0x1000, 0x00200001,
    0x1100, 0x00200002,
    0x1200, GUM_TEST_PDATA_RVA | 3,
    0x1300, GUM_TEST_XDATA (0),
    0x1400, GUM_TEST_XDATA (3),
    0x1500, GUM_TEST_XDATA (6),
    0x1600, GUM_TEST_XDATA (8),
    0x1700, GUM_TEST_XDATA (13),
  };
  const guint32 xdata[] = {
    GUM_TEST_ARM64_XDATA_HEADER (0, 1, 1),
    0,
    GUM_TEST_ARM64_END,

    GUM_TEST_ARM64_XDATA_HEADER (0, 1, 1),
    0,
    GUM_TEST_ARM64_END_C | (GUM_TEST_ARM64_END << 8),

    GUM_TEST_ARM64_XDATA_HEADER (1, 0, 1),
    GUM_TEST_ARM64_END_C | (GUM_TEST_ARM64_END << 8),

    GUM_TEST_ARM64_XDATA_HEADER (0, 0, 0),
    2 | (1 << 16),
    0,
    0,
    GUM_TEST_ARM64_END_C | (GUM_TEST_ARM64_END << 8),

    GUM_TEST_ARM64_XDATA_HEADER (0, 0, 0),
    1 | (1 << 16),
    GUM_TEST_ARM64_END_C,
    GUM_TEST_ARM64_END,
  };
  const guint32 expected[] = { 0x1000, 0x1300, 0x1700 };
  GumPeModule * module;
  GArray * starts;

  module = gum_test_make_pe_module (GUM_PE_MACHINE_ARM64, pdata, sizeof (pdata),
      xdata, sizeof (xdata));
  starts = gum_test_collect_function_starts (module);

  gum_test_assert_function_starts (starts, expected, G_N_ELEMENTS (expected));

  g_array_unref (starts);
  g_object_unref (module);
}

TESTCASE (arm_function_starts_skip_fragments)
{
  const guint32 pdata[] = {
    0x1001, 0x00200001,
    0x1101, 0x00200002,
    0x1201, GUM_TEST_XDATA (0),
    0x1301, GUM_TEST_XDATA (1),
  };
  const guint32 xdata[] = {
    0x00000010,
    0x00000010 | GUM_TEST_ARM_XDATA_FRAGMENT,
  };
  const guint32 expected[] = { 0x1001, 0x1201 };
  GumPeModule * module;
  GArray * starts;

  module = gum_test_make_pe_module (GUM_PE_MACHINE_ARMNT, pdata, sizeof (pdata),
      xdata, sizeof (xdata));
  starts = gum_test_collect_function_starts (module);

  gum_test_assert_function_starts (starts, expected, G_N_ELEMENTS (expected));

  g_array_unref (starts);
  g_object_unref (module);
}

#if defined (HAVE_WINDOWS) && GLIB_SIZEOF_VOID_P == 8

TESTCASE (function_starts_include_system_exports)
{
  g_assert_cmpuint (gum_test_check_exports_are_function_starts ("ntdll.dll"),
      >, 500);
  g_assert_cmpuint (
      gum_test_check_exports_are_function_starts ("kernelbase.dll"), >, 500);
}

static guint
gum_test_check_exports_are_function_starts (const gchar * module_name)
{
  GumTestExportCheckContext ctx;
  GumPeModule * module;
  GArray * starts;
  guint i;

  ctx.base = GUM_ADDRESS (GetModuleHandleA (module_name));
  ctx.starts = g_hash_table_new (NULL, NULL);
  ctx.num_checked = 0;

  module = gum_pe_module_new_from_memory (ctx.base, NULL);
  starts = gum_test_collect_function_starts (module);
  for (i = 0; i != starts->len; i++)
  {
    g_hash_table_add (ctx.starts,
        GSIZE_TO_POINTER (g_array_index (starts, guint32, i)));
  }

  gum_pe_module_enumerate_exports (module,
      gum_test_check_export_is_function_start, &ctx);

  g_array_unref (starts);
  g_object_unref (module);
  g_hash_table_unref (ctx.starts);

  return ctx.num_checked;
}

static gboolean
gum_test_check_export_is_function_start (const GumPeExportDetails * details,
                                         gpointer user_data)
{
  GumTestExportCheckContext * ctx = user_data;
  DWORD64 image_base;
  PRUNTIME_FUNCTION entry;

  if (details->type != GUM_PE_EXPORT_REGULAR)
    return TRUE;

  entry = RtlLookupFunctionEntry (ctx->base + details->rva, &image_base, NULL);
  if (entry == NULL || entry->BeginAddress != details->rva)
    return TRUE;

  if (!g_hash_table_contains (ctx->starts, GSIZE_TO_POINTER (details->rva)))
  {
    g_error ("%s (RVA 0x%x) not reported as a function start",
        (details->name != NULL) ? details->name : "<ordinal>", details->rva);
  }

  ctx->num_checked++;

  return TRUE;
}

#endif

static GumPeModule *
gum_test_make_pe_module (GumPeMachine machine,
                         const guint32 * pdata,
                         gsize pdata_size,
                         const guint32 * xdata,
                         gsize xdata_size)
{
  GumPeModule * module;
  guint8 * image;
  gboolean is_pe32_plus = machine != GUM_PE_MACHINE_ARMNT;
  guint8 * file_header, * optional_header;
  guint directories_offset;
  GBytes * blob;

  image = g_malloc0 (GUM_TEST_IMAGE_SIZE);

  image[0] = 'M';
  image[1] = 'Z';
  *((guint32 *) (image + 0x3c)) = GUM_TEST_NT_OFFSET;

  memcpy (image + GUM_TEST_NT_OFFSET, "PE\0\0", 4);

  file_header = image + GUM_TEST_NT_OFFSET + 4;
  *((guint16 *) (file_header + 0)) = machine;
  *((guint16 *) (file_header + 16)) = is_pe32_plus ? 0xf0 : 0xe0;

  optional_header = file_header + 20;
  *((guint16 *) (optional_header + 0)) = is_pe32_plus ? 0x20b : 0x10b;
  *((guint32 *) (optional_header + 56)) = GUM_TEST_IMAGE_SIZE;
  *((guint32 *) (optional_header + 60)) = GUM_TEST_IMAGE_SIZE;
  if (is_pe32_plus)
  {
    *((guint32 *) (optional_header + 108)) = 16;
    directories_offset = 112;
  }
  else
  {
    *((guint32 *) (optional_header + 92)) = 16;
    directories_offset = 96;
  }
  *((guint32 *) (optional_header + directories_offset +
      (GUM_PE_DIRECTORY_EXCEPTION * 8))) = GUM_TEST_PDATA_RVA;
  *((guint32 *) (optional_header + directories_offset +
      (GUM_PE_DIRECTORY_EXCEPTION * 8) + 4)) = pdata_size;

  memcpy (image + GUM_TEST_PDATA_RVA, pdata, pdata_size);
  memcpy (image + GUM_TEST_XDATA_RVA, xdata, xdata_size);

  blob = g_bytes_new_take (image, GUM_TEST_IMAGE_SIZE);
  module = gum_pe_module_new_from_blob (blob, NULL);
  g_assert_nonnull (module);
  g_bytes_unref (blob);

  return module;
}

static GArray *
gum_test_collect_function_starts (GumPeModule * module)
{
  GArray * starts = g_array_new (FALSE, FALSE, sizeof (guint32));

  gum_pe_module_enumerate_function_starts (module,
      gum_test_collect_function_start, starts);

  return starts;
}

static gboolean
gum_test_collect_function_start (GumAddress rva,
                                 gpointer user_data)
{
  GArray * starts = user_data;
  guint32 start = rva;

  g_array_append_val (starts, start);

  return TRUE;
}

static void
gum_test_assert_function_starts (GArray * starts,
                                 const guint32 * expected,
                                 guint n)
{
  guint i;

  g_assert_cmpuint (starts->len, ==, n);
  for (i = 0; i != n; i++)
    g_assert_cmphex (g_array_index (starts, guint32, i), ==, expected[i]);
}
