/*
 * Copyright (C) 2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "capstone-fixture.c"

TESTLIST_BEGIN (capstone)
#if defined (HAVE_I386)
  TESTENTRY (simple_x86_instruction_should_be_supported)
  TESTENTRY (vbroadcasti128_instructions_should_be_unsupported_for_now)
#elif defined (HAVE_ARM)
  TESTENTRY (simple_thumb_instruction_should_be_supported)
  TESTENTRY (ldaex_stlex_instructions_should_be_unsupported_for_now)
#elif defined (HAVE_ARM64)
  TESTENTRY (simple_instruction_should_be_supported)
  TESTENTRY (cas_instructions_should_be_unsupported_for_now)
#endif
TESTLIST_END ()

#if defined (HAVE_I386)

TESTCASE (simple_x86_instruction_should_be_supported)
{
  const guint8 nop[] = { 0x90 };
  DECODE (nop);
  EXPECT (X86_INS_NOP, "nop");
  g_assert_cmpuint (fixture->insn->size, ==, 1);
}

TESTCASE (vbroadcasti128_instructions_should_be_unsupported_for_now)
{
  const guint8 vbroadcast6[] = { 0xc4, 0xe2, 0x7d, 0x5a, 0x0c, 0x0e };
  const guint8 vbroadcast7[] = { 0xc4, 0x02, 0x7d, 0x5a, 0x44, 0x05, 0x00 };

  DECODE (vbroadcast6);
  EXPECT (X86_INS_NOP, "<bug> vbroadcasti128 instructions missing in capstone");
  g_assert_cmpuint (fixture->insn->size, ==, 6);

  DECODE (vbroadcast7);
  EXPECT (X86_INS_NOP, "<bug> vbroadcasti128 instructions missing in capstone");
  g_assert_cmpuint (fixture->insn->size, ==, 7);
}

#elif defined (HAVE_ARM)

TESTCASE (simple_thumb_instruction_should_be_supported)
{
  DECODE (0xbe00);
  EXPECT (ARM_INS_BKPT, "bkpt #0");
  g_assert_cmpuint (fixture->insn->size, ==, 2);
}

TESTCASE (ldaex_stlex_instructions_should_be_unsupported_for_now)
{
  DECODE_T2 (0xe8d0, 0x0fef);
  EXPECT (ARM_INS_NOP, "<bug> ldaex instructions missing in capstone");
  g_assert_cmpuint (fixture->insn->size, ==, 4);

  DECODE_T2 (0xe8c0, 0x0fe0);
  EXPECT (ARM_INS_NOP, "<bug> stlex instructions missing in capstone");
  g_assert_cmpuint (fixture->insn->size, ==, 4);
}

#elif defined (HAVE_ARM64)

TESTCASE (simple_instruction_should_be_supported)
{
  DECODE (0xd10243ff);
  EXPECT (ARM64_INS_SUB, "sub sp, sp, #0x90");
}

TESTCASE (cas_instructions_should_be_unsupported_for_now)
{
  DECODE (0x88ea7e69); /* casa w10, w9, [x19] */
  EXPECT (ARM64_INS_NOP, "<bug> cas instructions missing in capstone");

  DECODE (0xc8e9fd1f); /* casal x9, xzr, [x8] */
  EXPECT (ARM64_INS_NOP, "<bug> cas instructions missing in capstone");
}

#endif
