/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#include "gummachomodule-priv.h"

#include <glib/gstdio.h>

#define TESTCASE(NAME) \
    void test_macho_module_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/MachoModule", test_macho_module, NAME)

#define GUM_TEST_IMAGE_SIZE 0x1000

TESTLIST_BEGIN (macho_module)
  TESTENTRY (out_of_range_fat_slice_is_rejected)
TESTLIST_END ()

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
