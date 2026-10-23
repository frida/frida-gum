/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <unistd.h>

static int gum_test_elf_magic = 0;

__attribute__ ((constructor)) static void
gum_test_elf_on_load (void)
{
  gum_test_elf_magic = 0x1337;
}

__attribute__ ((destructor)) static void
gum_test_elf_on_unload (void)
{
  gum_test_elf_magic = 0;
}

int
gum_test_elf_sum (int a,
                  int b)
{
  return a + b;
}

int
gum_test_elf_get_magic (void)
{
  return gum_test_elf_magic;
}

__thread int gum_test_elf_tls_value = 0x1234;

int
gum_test_elf_tls_get (void)
{
  return gum_test_elf_tls_value;
}

void
gum_test_elf_tls_set (int value)
{
  gum_test_elf_tls_value = value;
}

unsigned int
gum_test_elf_get_pid (void)
{
  return getpid ();
}
