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

TESTLIST_BEGIN (macho_module)
  TESTENTRY (dylib_name_is_read_from_its_offset)
  TESTENTRY (unterminated_dylib_name_is_rejected)
  TESTENTRY (out_of_range_fat_slice_is_rejected)
TESTLIST_END ()

static guint8 * gum_test_make_macho_image (void);
static void gum_test_add_load_command (guint8 * image, gconstpointer command,
    gsize size);
static GumMachoModule * gum_test_load_macho_image (guint8 * image);
static GumMachoModule * gum_test_try_load_macho_image (guint8 * image);

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
  GumSegmentCommand64 text = { 0, };

  image = g_malloc0 (GUM_TEST_IMAGE_SIZE);

  header = (GumMachHeader64 *) image;
  header->magic = GUM_MH_MAGIC_64;
  header->cputype = GUM_MACHO_CPU_ARM64;
  header->filetype = GUM_MH_EXECUTE;

  text.cmd = GUM_LC_SEGMENT_64;
  text.cmdsize = sizeof (text);
  strcpy (text.segname, "__TEXT");
  text.vmsize = GUM_TEST_IMAGE_SIZE;
  text.filesize = GUM_TEST_IMAGE_SIZE;
  gum_test_add_load_command (image, &text, sizeof (text));

  return image;
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
