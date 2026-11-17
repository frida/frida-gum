/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#include "gummachomodule-priv.h"

#include <glib/gstdio.h>
#include <string.h>

#define TESTCASE(NAME) \
    void test_macho_module_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/MachoModule", test_macho_module, NAME)

#define GUM_TEST_IMAGE_SIZE 0x1000
#define GUM_TEST_DATA_OFFSET 0x800
#define GUM_TEST_STRINGS_OFFSET 0x900

TESTLIST_BEGIN (macho_module)
  TESTENTRY (symbols_with_malformed_names_are_skipped)
  TESTENTRY (out_of_range_symbol_table_is_ignored)
  TESTENTRY (cyclic_export_trie_is_visited_once)
  TESTENTRY (malformed_export_trie_is_ignored)
  TESTENTRY (out_of_range_export_trie_is_ignored)
  TESTENTRY (unterminated_bind_symbol_ends_enumeration)
  TESTENTRY (rebase_repeats_stay_within_segment)
  TESTENTRY (out_of_range_function_starts_are_skipped)
  TESTENTRY (dylib_name_is_read_from_its_offset)
  TESTENTRY (unterminated_dylib_name_is_rejected)
  TESTENTRY (out_of_range_fat_slice_is_rejected)
TESTLIST_END ()

static guint8 * gum_test_make_macho_image (void);
static void gum_test_add_segment (guint8 * image, const gchar * name);
static void gum_test_add_load_command (guint8 * image, gconstpointer command,
    gsize size);
static void gum_test_add_symtab (guint8 * image, guint32 symoff, guint32 nsyms,
    guint32 stroff, guint32 strsize);
static void gum_test_add_exports_trie (guint8 * image, guint32 dataoff,
    guint32 datasize);
static GumMachoModule * gum_test_load_macho_image (guint8 * image);
static GumMachoModule * gum_test_try_load_macho_image (guint8 * image);
static gboolean gum_test_count_symbol (const GumMachoSymbolDetails * details,
    gpointer user_data);
static gboolean gum_test_count_export (const GumMachoExportDetails * details,
    gpointer user_data);
static gboolean gum_test_count_bind (const GumMachoBindDetails * details,
    gpointer user_data);
static gboolean gum_test_count_rebase (const GumMachoRebaseDetails * details,
    gpointer user_data);
static gboolean gum_test_count_function_starts (
    const GumMachoFunctionStartsDetails * details, gpointer user_data);

TESTCASE (symbols_with_malformed_names_are_skipped)
{
  const gchar strings[8] = { '\0', '_', 'a', '\0', 'z', 'z', 'z', 'z' };
  const guint32 name_offsets[] = { 1, 0x100, 4 };
  guint8 * image;
  GumNList64 * symbols;
  guint i;
  GumMachoModule * module;
  guint count = 0;

  image = gum_test_make_macho_image ();
  symbols = (GumNList64 *) (image + GUM_TEST_DATA_OFFSET);
  for (i = 0; i != G_N_ELEMENTS (name_offsets); i++)
    symbols[i].n_strx = name_offsets[i];
  memcpy (image + GUM_TEST_STRINGS_OFFSET, strings, sizeof (strings));
  gum_test_add_symtab (image, GUM_TEST_DATA_OFFSET,
      G_N_ELEMENTS (name_offsets), GUM_TEST_STRINGS_OFFSET, sizeof (strings));
  module = gum_test_load_macho_image (image);

  gum_macho_module_enumerate_symbols (module, gum_test_count_symbol, &count);
  g_assert_cmpuint (count, ==, 1);

  g_object_unref (module);
}

TESTCASE (out_of_range_symbol_table_is_ignored)
{
  guint8 * image;
  GumMachoModule * module;
  guint count = 0;

  image = gum_test_make_macho_image ();
  gum_test_add_symtab (image, GUM_TEST_IMAGE_SIZE - sizeof (GumNList64), 2,
      GUM_TEST_STRINGS_OFFSET, 8);
  module = gum_test_load_macho_image (image);

  gum_macho_module_enumerate_symbols (module, gum_test_count_symbol, &count);
  g_assert_cmpuint (count, ==, 0);

  g_object_unref (module);
}

TESTCASE (cyclic_export_trie_is_visited_once)
{
  const guint8 trie[] = {
    0x00, 0x01, '_', 'a', '\0', 0x06,
    0x02, 0x00, 0x10, 0x01, 'b', '\0', 0x06,
  };
  guint8 * image;
  GumMachoModule * module;
  guint count = 0;
  GumMachoExportDetails details;

  image = gum_test_make_macho_image ();
  memcpy (image + GUM_TEST_DATA_OFFSET, trie, sizeof (trie));
  gum_test_add_exports_trie (image, GUM_TEST_DATA_OFFSET, sizeof (trie));
  module = gum_test_load_macho_image (image);

  gum_macho_module_enumerate_exports (module, gum_test_count_export, &count);
  g_assert_cmpuint (count, ==, 1);

  g_assert_true (gum_macho_module_resolve_export (module, "_a", &details));
  g_assert_cmpuint (details.offset, ==, 0x10);
  g_assert_false (gum_macho_module_resolve_export (module, "_ac", &details));

  g_object_unref (module);
}

TESTCASE (malformed_export_trie_is_ignored)
{
  const guint8 trie[] = {
    0x00, 0x02, '_', 'a', '\0', 0x40,
    '_', 'b',
  };
  guint8 * image;
  GumMachoModule * module;
  guint count = 0;
  GumMachoExportDetails details;

  image = gum_test_make_macho_image ();
  memcpy (image + GUM_TEST_DATA_OFFSET, trie, sizeof (trie));
  memset (image + GUM_TEST_DATA_OFFSET + sizeof (trie), 'c', 16);
  gum_test_add_exports_trie (image, GUM_TEST_DATA_OFFSET, sizeof (trie));
  module = gum_test_load_macho_image (image);

  gum_macho_module_enumerate_exports (module, gum_test_count_export, &count);
  g_assert_cmpuint (count, ==, 0);

  g_assert_false (gum_macho_module_resolve_export (module, "_a", &details));
  g_assert_false (gum_macho_module_resolve_export (module, "_b", &details));

  g_object_unref (module);
}

TESTCASE (out_of_range_export_trie_is_ignored)
{
  const guint32 trie_offset = GUM_TEST_IMAGE_SIZE - 0x10;
  guint8 * image;
  GumMachoModule * module;
  guint count = 0;

  image = gum_test_make_macho_image ();
  image[trie_offset + 1] = 1;
  memset (image + trie_offset + 2, 'x', GUM_TEST_IMAGE_SIZE - trie_offset - 2);
  gum_test_add_exports_trie (image, trie_offset, 0x100);
  module = gum_test_load_macho_image (image);

  gum_macho_module_enumerate_exports (module, gum_test_count_export, &count);
  g_assert_cmpuint (count, ==, 0);

  g_object_unref (module);
}

TESTCASE (unterminated_bind_symbol_ends_enumeration)
{
  const guint8 binds[] = {
    GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, 'a', 'b', 'c',
  };
  const guint32 binds_offset = GUM_TEST_IMAGE_SIZE - sizeof (binds);
  guint8 * image;
  GumDyldInfoCommand info = { 0, };
  GumMachoModule * module;
  guint count = 0;

  image = gum_test_make_macho_image ();
  memcpy (image + binds_offset, binds, sizeof (binds));
  info.cmd = GUM_LC_DYLD_INFO_ONLY;
  info.cmdsize = sizeof (info);
  info.bind_off = binds_offset;
  info.bind_size = sizeof (binds);
  gum_test_add_load_command (image, &info, sizeof (info));
  module = gum_test_load_macho_image (image);

  gum_macho_module_enumerate_binds (module, gum_test_count_bind, &count);
  g_assert_cmpuint (count, ==, 0);

  g_object_unref (module);
}

TESTCASE (rebase_repeats_stay_within_segment)
{
  const guint8 rebases[] = {
    GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
  };
  guint8 * image;
  GumDyldInfoCommand info = { 0, };
  GumMachoModule * module;
  guint count = 0;

  image = gum_test_make_macho_image ();
  memcpy (image + GUM_TEST_DATA_OFFSET, rebases, sizeof (rebases));
  info.cmd = GUM_LC_DYLD_INFO_ONLY;
  info.cmdsize = sizeof (info);
  info.rebase_off = GUM_TEST_DATA_OFFSET;
  info.rebase_size = sizeof (rebases);
  gum_test_add_load_command (image, &info, sizeof (info));
  module = gum_test_load_macho_image (image);

  gum_macho_module_enumerate_rebases (module, gum_test_count_rebase, &count);
  g_assert_cmpuint (count, ==, GUM_TEST_IMAGE_SIZE / 8);

  g_object_unref (module);
}

TESTCASE (out_of_range_function_starts_are_skipped)
{
  const guint32 ranges[][2] = {
    { GUM_TEST_DATA_OFFSET, 4 },
    { GUM_TEST_IMAGE_SIZE - 4, 8 },
  };
  guint8 * image;
  guint i;
  GumMachoModule * module;
  guint count = 0;

  image = gum_test_make_macho_image ();
  for (i = 0; i != G_N_ELEMENTS (ranges); i++)
  {
    GumLinkeditDataCommand starts = { 0, };

    starts.cmd = GUM_LC_FUNCTION_STARTS;
    starts.cmdsize = sizeof (starts);
    starts.dataoff = ranges[i][0];
    starts.datasize = ranges[i][1];
    gum_test_add_load_command (image, &starts, sizeof (starts));
  }
  module = gum_test_load_macho_image (image);

  gum_macho_module_enumerate_function_starts (module,
      gum_test_count_function_starts, &count);
  g_assert_cmpuint (count, ==, 1);

  g_object_unref (module);
}

TESTCASE (dylib_name_is_read_from_its_offset)
{
  guint8 command[sizeof (GumDylibCommand) + 16] = { 0, };
  GumDylibCommand * dc = (GumDylibCommand *) command;
  guint8 * image;
  GumMachoModule * module;

  dc->cmd = GUM_LC_ID_DYLIB;
  dc->cmdsize = sizeof (command);
  dc->dylib.name.offset = sizeof (GumDylibCommand) + 4;
  memset (command + sizeof (GumDylibCommand), 'x', 4);
  memcpy (command + dc->dylib.name.offset, "libfoo", 7);

  image = gum_test_make_macho_image ();
  gum_test_add_load_command (image, command, sizeof (command));
  module = gum_test_load_macho_image (image);

  g_assert_cmpstr (module->name, ==, "libfoo");

  g_object_unref (module);
}

TESTCASE (unterminated_dylib_name_is_rejected)
{
  guint8 command[sizeof (GumDylibCommand) + 8];
  GumDylibCommand * dc = (GumDylibCommand *) command;
  guint8 * image;

  memset (command, 'x', sizeof (command));
  dc->cmd = GUM_LC_ID_DYLIB;
  dc->cmdsize = sizeof (command);
  dc->dylib.name.offset = sizeof (GumDylibCommand);

  image = gum_test_make_macho_image ();
  gum_test_add_load_command (image, command, sizeof (command));

  g_assert_null (gum_test_try_load_macho_image (image));
}

TESTCASE (out_of_range_fat_slice_is_rejected)
{
  guint8 * image;
  GumFatHeader * fat_header;
  GumFatArch32 * fat_arch;
  gint fd;
  gchar * path;
  GumMachoModule * module;
  GError * error = NULL;

  image = g_malloc0 (GUM_TEST_IMAGE_SIZE);
  fat_header = (GumFatHeader *) image;
  fat_header->magic = GUM_FAT_CIGAM_32;
  fat_header->nfat_arch = GUINT32_TO_BE (1);
  fat_arch = (GumFatArch32 *) (fat_header + 1);
  fat_arch->cputype = GUINT32_TO_BE (GUM_MACHO_CPU_ARM64);
  fat_arch->offset = GUINT32_TO_BE (0x40000000);
  fat_arch->size = GUINT32_TO_BE (GUM_TEST_IMAGE_SIZE);

  fd = g_file_open_tmp ("machomodule-XXXXXX", &path, NULL);
  g_assert_cmpint (fd, !=, -1);
  g_close (fd, NULL);
  g_assert_true (g_file_set_contents (path, (const gchar *) image,
      GUM_TEST_IMAGE_SIZE, NULL));

  module = gum_macho_module_new_from_file (path, GUM_CPU_ARM64,
      GUM_PTRAUTH_INVALID, GUM_MACHO_MODULE_FLAGS_HEADER_ONLY, &error);
  g_assert_null (module);
  g_assert_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT);

  g_error_free (error);
  g_unlink (path);
  g_free (path);
  g_free (image);
}

static guint8 *
gum_test_make_macho_image (void)
{
  guint8 * image;
  GumMachHeader64 * header;

  image = g_malloc0 (GUM_TEST_IMAGE_SIZE);

  header = (GumMachHeader64 *) image;
  header->magic = GUM_MH_MAGIC_64;
  header->cputype = GUM_MACHO_CPU_ARM64;
  header->filetype = GUM_MH_EXECUTE;

  gum_test_add_segment (image, "__TEXT");
  gum_test_add_segment (image, "__LINKEDIT");

  return image;
}

static void
gum_test_add_segment (guint8 * image,
                      const gchar * name)
{
  GumSegmentCommand64 segment = { 0, };

  segment.cmd = GUM_LC_SEGMENT_64;
  segment.cmdsize = sizeof (segment);
  strcpy (segment.segname, name);
  segment.vmsize = GUM_TEST_IMAGE_SIZE;
  segment.filesize = GUM_TEST_IMAGE_SIZE;

  gum_test_add_load_command (image, &segment, sizeof (segment));
}

static void
gum_test_add_load_command (guint8 * image,
                           gconstpointer command,
                           gsize size)
{
  GumMachHeader64 * header = (GumMachHeader64 *) image;

  memcpy (image + sizeof (GumMachHeader64) + header->sizeofcmds, command,
      size);
  header->ncmds++;
  header->sizeofcmds += size;
}

static void
gum_test_add_symtab (guint8 * image,
                     guint32 symoff,
                     guint32 nsyms,
                     guint32 stroff,
                     guint32 strsize)
{
  GumSymtabCommand symtab = { 0, };

  symtab.cmd = GUM_LC_SYMTAB;
  symtab.cmdsize = sizeof (symtab);
  symtab.symoff = symoff;
  symtab.nsyms = nsyms;
  symtab.stroff = stroff;
  symtab.strsize = strsize;

  gum_test_add_load_command (image, &symtab, sizeof (symtab));
}

static void
gum_test_add_exports_trie (guint8 * image,
                           guint32 dataoff,
                           guint32 datasize)
{
  GumLinkeditDataCommand trie = { 0, };

  trie.cmd = GUM_LC_DYLD_EXPORTS_TRIE;
  trie.cmdsize = sizeof (trie);
  trie.dataoff = dataoff;
  trie.datasize = datasize;

  gum_test_add_load_command (image, &trie, sizeof (trie));
}

static GumMachoModule *
gum_test_load_macho_image (guint8 * image)
{
  GumMachoModule * module;

  module = gum_test_try_load_macho_image (image);
  g_assert_nonnull (module);

  return module;
}

static GumMachoModule *
gum_test_try_load_macho_image (guint8 * image)
{
  GumMachoModule * module;
  GBytes * blob;

  blob = g_bytes_new_take (image, GUM_TEST_IMAGE_SIZE);
  module = gum_macho_module_new_from_blob (blob, GUM_CPU_ARM64,
      GUM_PTRAUTH_INVALID, GUM_MACHO_MODULE_FLAGS_NONE, NULL);
  g_bytes_unref (blob);

  return module;
}

static gboolean
gum_test_count_symbol (const GumMachoSymbolDetails * details,
                       gpointer user_data)
{
  guint * count = user_data;

  g_assert_cmpstr (details->name, ==, "_a");
  (*count)++;

  return TRUE;
}

static gboolean
gum_test_count_export (const GumMachoExportDetails * details,
                       gpointer user_data)
{
  guint * count = user_data;

  (*count)++;

  return TRUE;
}

static gboolean
gum_test_count_bind (const GumMachoBindDetails * details,
                     gpointer user_data)
{
  guint * count = user_data;

  (*count)++;

  return TRUE;
}

static gboolean
gum_test_count_rebase (const GumMachoRebaseDetails * details,
                       gpointer user_data)
{
  guint * count = user_data;

  (*count)++;

  return TRUE;
}

static gboolean
gum_test_count_function_starts (const GumMachoFunctionStartsDetails * details,
                                gpointer user_data)
{
  guint * count = user_data;

  g_assert_cmpuint (details->file_offset, ==, GUM_TEST_DATA_OFFSET);
  (*count)++;

  return TRUE;
}
