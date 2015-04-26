/*
 * Copyright (C) 2009-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "relocator-fixture.c"

TEST_LIST_BEGIN (relocator)
  RELOCATOR_TESTENTRY (one_to_one)
  RELOCATOR_TESTENTRY (call_near_relative)
  RELOCATOR_TESTENTRY (call_near_relative_to_next_instruction)
  RELOCATOR_TESTENTRY (call_near_gnu_get_pc_thunk)
  RELOCATOR_TESTENTRY (call_near_android_get_pc_thunk)
  RELOCATOR_TESTENTRY (call_near_indirect)
  RELOCATOR_TESTENTRY (jmp_short_outside_block)
  RELOCATOR_TESTENTRY (jmp_near_outside_block)
  RELOCATOR_TESTENTRY (jmp_register)
  RELOCATOR_TESTENTRY (jmp_indirect)
  RELOCATOR_TESTENTRY (jcc_short_within_block)
  RELOCATOR_TESTENTRY (jcc_short_outside_block)
  RELOCATOR_TESTENTRY (jcc_near_outside_block)
  RELOCATOR_TESTENTRY (jcxz_short_within_block)
  RELOCATOR_TESTENTRY (jcxz_short_outside_block)
  RELOCATOR_TESTENTRY (peek_next_write)
  RELOCATOR_TESTENTRY (skip_instruction)
  RELOCATOR_TESTENTRY (eob_and_eoi_on_jmp)
  RELOCATOR_TESTENTRY (eob_but_not_eoi_on_call)
  RELOCATOR_TESTENTRY (eob_and_eoi_on_ret)
  RELOCATOR_TESTENTRY (eob_but_not_eoi_on_jcc)
  RELOCATOR_TESTENTRY (eob_but_not_eoi_on_jcxz)

#if GLIB_SIZEOF_VOID_P == 8
  RELOCATOR_TESTENTRY (rip_relative_move_different_target)
  RELOCATOR_TESTENTRY (rip_relative_move_same_target)
  RELOCATOR_TESTENTRY (rip_relative_push)
  RELOCATOR_TESTENTRY (rip_relative_push_red_zone)
  RELOCATOR_TESTENTRY (rip_relative_cmpxchg)
#endif
TEST_LIST_END ()

RELOCATOR_TESTCASE (one_to_one)
{
  guint8 input[] = {
    0x55,                         /* push ebp     */
    0x8b, 0xec,                   /* mov ebp, esp */
  };
  const cs_insn * insn;

  SETUP_RELOCATOR_WITH (input);

  insn = NULL;
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, &insn), ==, 1);
  g_assert_cmpint (insn->id, ==, X86_INS_PUSH);
  assert_outbuf_still_zeroed_from_offset (0);

  insn = NULL;
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, &insn), ==, 3);
  g_assert_cmpint (insn->id, ==, X86_INS_MOV);
  assert_outbuf_still_zeroed_from_offset (0);

  g_assert (gum_x86_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output, input, 1), ==, 0);
  assert_outbuf_still_zeroed_from_offset (1);

  g_assert (gum_x86_relocator_write_one (&fixture->rl));
  g_assert_cmpint (memcmp (fixture->output + 1, input + 1, 2), ==, 0);
  assert_outbuf_still_zeroed_from_offset (3);

  g_assert (!gum_x86_relocator_write_one (&fixture->rl));
}

RELOCATOR_TESTCASE (call_near_relative)
{
  guint8 input[] = {
    0x55,                         /* push ebp     */
    0x8b, 0xec,                   /* mov ebp, esp */
    0xe8, 0x04, 0x00, 0x00, 0x00, /* call dummy   */
    0x8b, 0xe5,                   /* mov esp, ebp */
    0x5d,                         /* pop ebp      */
    0xc3,                         /* retn         */

/* dummy:                                         */
    0xc3                          /* retn         */
  };
  gint32 reloc_distance, expected_distance;

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 8);

  gum_x86_relocator_write_all (&fixture->rl);
  g_assert_cmpint (memcmp (fixture->output + 3, input + 3, 5), !=, 0);
  reloc_distance = *((gint32 *) (fixture->output + 4));
  expected_distance =
      ((gssize) (input + 12)) - ((gssize) (fixture->output + 8));
  g_assert_cmpint (reloc_distance, ==, expected_distance);
}

RELOCATOR_TESTCASE (call_near_relative_to_next_instruction)
{
  guint8 input[] = {
    0xe8, 0x00, 0x00, 0x00, 0x00, /* call +0         */
    0x59                          /* pop xcx         */
  };
#if GLIB_SIZEOF_VOID_P == 8
  guint8 expected_output[] = {
    0x50,                         /* push rax        */
    0x48, 0xb8,                   /* mov rax, <imm>  */
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00,
    0x48, 0x87, 0x04, 0x24        /* xchg rax, [rsp] */
  };

  *((gpointer *) (expected_output + 3)) = input + 5;
#else
  guint8 expected_output[] = {
    0x68, 0x00, 0x00, 0x00, 0x00  /* push <imm> */
  };

  *((gpointer *) (expected_output + 1)) = input + 5;
#endif

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 5);
  g_assert (!gum_x86_relocator_eob (&fixture->rl));
  gum_x86_relocator_write_all (&fixture->rl);
  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==,
      sizeof (expected_output));
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

RELOCATOR_TESTCASE (call_near_gnu_get_pc_thunk)
{
  const guint8 input[] = {
    0xe8, 0x01, 0x00, 0x00, 0x00, /* call +1         */

    0xcc,                         /* int 3          */
    0x8b, 0x0c, 0x24,             /* mov ecx, [esp] */
    0xc3                          /* ret            */
  };
  guint8 expected_output[] = {
    0xb9, 0x00, 0x00, 0x00, 0x00  /* mov ecx, <imm> */
  };

  *((guint32 *) (expected_output + 1)) = GPOINTER_TO_SIZE (input + 5);

  gum_x86_writer_set_target_cpu (&fixture->cw, GUM_CPU_IA32);
  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 5);
  g_assert (!gum_x86_relocator_eob (&fixture->rl));
  gum_x86_relocator_write_all (&fixture->rl);
  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==,
      sizeof (expected_output));
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

RELOCATOR_TESTCASE (call_near_android_get_pc_thunk)
{
  const guint8 input[] = {
    0xe8, 0x01, 0x00, 0x00, 0x00, /* call +1         */

    0xcc,                         /* int 3          */
    0x8b, 0x1c, 0x24,             /* mov ebx, [esp] */
    0xc3                          /* ret            */
  };
  guint8 expected_output[] = {
    0xbb, 0x00, 0x00, 0x00, 0x00  /* mov ebx, <imm> */
  };

  *((guint32 *) (expected_output + 1)) = GPOINTER_TO_SIZE (input + 5);

  gum_x86_writer_set_target_cpu (&fixture->cw, GUM_CPU_IA32);
  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 5);
  g_assert (!gum_x86_relocator_eob (&fixture->rl));
  gum_x86_relocator_write_all (&fixture->rl);
  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==,
      sizeof (expected_output));
  g_assert_cmpint (memcmp (fixture->output, expected_output,
      sizeof (expected_output)), ==, 0);
}

RELOCATOR_TESTCASE (call_near_indirect)
{
  guint8 input[] = {
    0xff, 0x15, 0x78, 0x56, 0x34, 0x12 /* call ds:012345678h */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 6);
  gum_x86_relocator_write_one (&fixture->rl);
  g_assert_cmpint (memcmp (fixture->output, input, 6), ==, 0);
}

RELOCATOR_TESTCASE (jmp_short_outside_block)
{
  guint8 input[] = {
    0xeb, 0x01  /* jmp +1 */
  };
  gint32 reloc_distance, expected_distance;

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==, 5);

  g_assert_cmphex (fixture->output[0], !=, input[0]);
  g_assert_cmphex (fixture->output[0], ==, 0xe9);

  reloc_distance = *((gint32 *) (fixture->output + 1));
  expected_distance =
      ((gssize) (input + 2 + 1)) - ((gssize) (fixture->output + 5));
  g_assert_cmpint (reloc_distance, ==, expected_distance);
}

RELOCATOR_TESTCASE (jmp_near_outside_block)
{
  guint8 input[] = {
    0xe9, 0x01, 0x00, 0x00, 0x00, /* jmp +1 */
  };
  gint32 reloc_distance, expected_distance;

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==, sizeof (input));

  g_assert_cmphex (fixture->output[0], ==, input[0]);

  reloc_distance = *((gint32 *) (fixture->output + 1));
  expected_distance =
      ((gssize) (input + 5 + 1)) - ((gssize) (fixture->output + 5));
  g_assert_cmpint (reloc_distance, ==, expected_distance);
}

RELOCATOR_TESTCASE (jmp_register)
{
  guint8 input[] = {
    0xff, 0xe0 /* jmp eax */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==, sizeof (input));
  g_assert_cmpint (memcmp (fixture->output, input, 2), ==, 0);
}

RELOCATOR_TESTCASE (jmp_indirect)
{
  guint8 input[] = {
#if GLIB_SIZEOF_VOID_P == 8
    0x48,
#endif
    0xff, 0x60, 0x08
  };

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), == , sizeof (input));
  g_assert_cmpint (memcmp (fixture->output, input, sizeof (input)), == , 0);
}

RELOCATOR_TESTCASE (jcc_short_within_block)
{
  guint8 input[] = {
    0x31, 0xc0,                         /* xor eax,eax */
    0x81, 0xfb, 0x2a, 0x00, 0x00, 0x00, /* cmp ebx, 42 */
    0x75, 0x02,                         /* jnz beach   */
    0xff, 0xc0,                         /* inc eax     */

/* beach:                                              */
    0xc3                                /* retn        */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 10);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==,
      sizeof (input));

  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_writer_put_inc_reg (&fixture->cw, GUM_REG_EAX);
  gum_x86_relocator_write_one (&fixture->rl);

  gum_x86_writer_flush (&fixture->cw);

  /* output should have one extra instruction of 2 bytes */
  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==,
      sizeof (input) + 2);

  /* the first 9 bytes should be the same */
  g_assert_cmpint (memcmp (fixture->output, input, 9), ==, 0);

  /* the jnz offset should be adjusted to account for the extra instruction */
  g_assert_cmpint ((gint8) fixture->output[9], ==, ((gint8) input[9]) + 2);

  /* the rest should be the same */
  g_assert_cmpint (memcmp (fixture->output + 10 + 2, input + 10, 3), ==, 0);
}

RELOCATOR_TESTCASE (jcc_short_outside_block)
{
  guint8 input[] = {
    0x75, 0xfd, /* jnz -3 */
    0xc3        /* retn   */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_all (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==, 6 + 1);
  g_assert_cmphex (fixture->output[0], ==, 0x0f);
  g_assert_cmphex (fixture->output[1], ==, 0x85);
  g_assert_cmpint (*((gint32 *) (fixture->output + 2)), ==,
      (gssize) (input - 1) - (gssize) (fixture->output + 6));
  g_assert_cmphex (fixture->output[6], ==, input[2]);
}

RELOCATOR_TESTCASE (jcc_near_outside_block)
{
  guint8 input[] = {
    0x0f, 0x84, 0xda, 0x00, 0x00, 0x00, /* jz +218 */
    0xc3                                /* retn    */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_all (&fixture->rl);

  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==, 6 + 1);
  g_assert_cmphex (fixture->output[0], ==, 0x0f);
  g_assert_cmphex (fixture->output[1], ==, 0x84);
  g_assert_cmpint (*((gint32 *) (fixture->output + 2)), ==,
      (gssize) (input + 6 + 218) - (gssize) (fixture->output + 6));
  g_assert_cmphex (fixture->output[6], ==, input[6]);
}

RELOCATOR_TESTCASE (jcxz_short_within_block)
{
  guint8 input[] = {
    0xe3, 0x02,                         /* jecxz/jrcxz beach */
    0xff, 0xc0,                         /* inc eax           */

/* beach:                                                    */
    0xc3                                /* retn              */
  };
  const guint8 expected_output[] = {
    0xe3, 0x04,                         /* jecxz/jrcxz beach */
    0xff, 0xc0,                         /* inc eax           */
    0xff, 0xc0,                         /* inc eax           */

/* beach:                                                    */
    0xc3                                /* retn              */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 4);
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 5);

  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_writer_put_inc_reg (&fixture->cw, GUM_REG_EAX);
  gum_x86_relocator_write_one (&fixture->rl);

  gum_x86_writer_flush (&fixture->cw);

  assert_output_equals (expected_output);
}

RELOCATOR_TESTCASE (jcxz_short_outside_block)
{
  guint8 input[] = {
    0xe3, 0xfd, /* jecxz/jrcxz -3      */
    0xc3        /* retn                */
  };
  guint8 expected_output[] = {
    0xe3, 0x02, /* jecxz/jrcxz is_true */
    0xeb, 0x05, /* jmp is_false        */

/* is_true:                            */
    0xe9, 0xaa, 0xaa, 0xaa, 0xaa,

/* is_false:                           */
    0xc3        /* retn                */
  };

  *((gint32 *) (expected_output + 5)) = (input - 1) - (fixture->output + 9);

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_all (&fixture->rl);

  gum_x86_writer_flush (&fixture->cw);

  assert_output_equals (expected_output);
}

RELOCATOR_TESTCASE (peek_next_write)
{
  guint8 input[] = {
    0x31, 0xc0, /* xor eax,eax */
    0xff, 0xc0  /* inc eax     */
  };

  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_read_one (&fixture->rl, NULL);

  g_assert_cmpint (gum_x86_relocator_peek_next_write_insn (&fixture->rl)->id,
      ==, X86_INS_XOR);
  gum_x86_relocator_write_one (&fixture->rl);
  g_assert_cmpint (gum_x86_relocator_peek_next_write_insn (&fixture->rl)->id,
      ==, X86_INS_INC);
  g_assert_cmpint (gum_x86_relocator_peek_next_write_insn (&fixture->rl)->id,
      ==, X86_INS_INC);
  g_assert (gum_x86_relocator_peek_next_write_source (&fixture->rl)
      == input + 2);
  g_assert (gum_x86_relocator_write_one (&fixture->rl));
  g_assert (gum_x86_relocator_peek_next_write_insn (&fixture->rl) == NULL);
  g_assert (gum_x86_relocator_peek_next_write_source (&fixture->rl) == NULL);
  g_assert (!gum_x86_relocator_write_one (&fixture->rl));
}

RELOCATOR_TESTCASE (skip_instruction)
{
  guint8 input[] = {
    0x31, 0xc0,                         /* xor eax,eax */
    0x81, 0xfb, 0x2a, 0x00, 0x00, 0x00, /* cmp ebx, 42 */
    0x75, 0x02,                         /* jnz beach   */
    0xff, 0xc0,                         /* inc eax     */

/* beach:                                              */
    0xc3                                /* retn        */
  };

  SETUP_RELOCATOR_WITH (input);

  while (!gum_x86_relocator_eoi (&fixture->rl))
    gum_x86_relocator_read_one (&fixture->rl, NULL);

  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_write_one (&fixture->rl);
  gum_x86_relocator_skip_one (&fixture->rl); /* skip retn */
  gum_x86_writer_put_inc_reg (&fixture->cw, GUM_REG_EAX); /* put "inc eax"
                                                            * there instead */

  gum_x86_writer_flush (&fixture->cw);

  /* output should be of almost the same size */
  g_assert_cmpuint (gum_x86_writer_offset (&fixture->cw), ==,
      sizeof (input) + 1);

  /* the first n - 1 bytes should be the same */
  g_assert_cmpint (memcmp (fixture->output, input, sizeof (input) - 1), ==, 0);
}

RELOCATOR_TESTCASE (eob_and_eoi_on_jmp)
{
  guint8 input[] = {
    0xeb, 0x01  /* jmp +1 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert (gum_x86_relocator_eob (&fixture->rl));
  g_assert (gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

RELOCATOR_TESTCASE (eob_but_not_eoi_on_call)
{
  guint8 input[] = {
    0xe8, 0x42, 0x00, 0x00, 0x00  /* call +0x42 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 5);
  g_assert (gum_x86_relocator_eob (&fixture->rl));
  g_assert (!gum_x86_relocator_eoi (&fixture->rl));
}

RELOCATOR_TESTCASE (eob_and_eoi_on_ret)
{
  guint8 input[] = {
    0xc2, 0x04, 0x00  /* retn 4 */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 3);
  g_assert (gum_x86_relocator_eob (&fixture->rl));
  g_assert (gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

RELOCATOR_TESTCASE (eob_but_not_eoi_on_jcc)
{
  guint8 input[] = {
    0x74, 0x01, /* jz +1  */
    0xc3        /* ret    */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert (gum_x86_relocator_eob (&fixture->rl));
  g_assert (!gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 3);
  g_assert (gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

RELOCATOR_TESTCASE (eob_but_not_eoi_on_jcxz)
{
  guint8 input[] = {
    0xe3, 0x01, /* jecxz/jrcxz +1 */
    0xc3        /* ret            */
  };

  SETUP_RELOCATOR_WITH (input);

  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 2);
  g_assert (gum_x86_relocator_eob (&fixture->rl));
  g_assert (!gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 3);
  g_assert (gum_x86_relocator_eoi (&fixture->rl));
  g_assert_cmpuint (gum_x86_relocator_read_one (&fixture->rl, NULL), ==, 0);
}

#if GLIB_SIZEOF_VOID_P == 8

RELOCATOR_TESTCASE (rip_relative_move_different_target)
{
  guint8 input[] = {
    0x8b, 0x15, 0x01, 0x00, 0x00, 0x00, /* mov edx, [rip + 1] */
    0xc3,                               /* ret                */
    0x01, 0x02, 0x03, 0x04
  };
  guint8 expected_output[] = {
    0x50,                               /* push rax           */
    0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, /* mov rax, <rip>     */
                0xff, 0xff, 0xff, 0xff,
    0x8b, 0x90, 0x01, 0x00, 0x00, 0x00, /* mov edx, [rax + 1] */
    0x58                                /* pop rax            */
  };

  *((gpointer *) (expected_output + 3)) = (gpointer) (input + 6);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_WINDOWS);
  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

RELOCATOR_TESTCASE (rip_relative_move_same_target)
{
  guint8 input[] = {
    0x8b, 0x05, 0x01, 0x00, 0x00, 0x00, /* mov eax, [rip + 1] */
    0xc3,                               /* ret                */
    0x01, 0x02, 0x03, 0x04
  };
  guint8 expected_output[] = {
    0x51,                               /* push rcx           */
    0x48, 0xb9, 0xff, 0xff, 0xff, 0xff, /* mov rcx, <rip>     */
                0xff, 0xff, 0xff, 0xff,
    0x8b, 0x81, 0x01, 0x00, 0x00, 0x00, /* mov eax, [rcx + 1] */
    0x59                                /* pop rcx            */
  };

  *((gpointer *) (expected_output + 3)) = (gpointer) (input + 6);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_WINDOWS);
  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

RELOCATOR_TESTCASE (rip_relative_push)
{
  const guint8 input[] = {
    0xff, 0x35,                         /* push [rip + imm32]   */
    0x01, 0x02, 0x03, 0x04
  };
  guint8 expected_output[] = {
    0x50,                               /* push rax  */
    0x50,                               /* push rax  */

    0x48, 0xb8,                         /* mov rax, <rip> */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0x48, 0x8b, 0x80,                   /* mov rax, [rax + <imm32>] */
    0x01, 0x02, 0x03, 0x04,

    0x48, 0x89, 0x44, 0x24, 0x08,       /* mov [rsp + 8], rax */
    0x58                                /* pop rax */
  };

  *((gpointer *) (expected_output + 4)) = (gpointer) (input + 6);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_WINDOWS);
  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

RELOCATOR_TESTCASE (rip_relative_push_red_zone)
{
  const guint8 input[] = {
    0xff, 0x35,                         /* push [rip + imm32]   */
    0x01, 0x02, 0x03, 0x04
  };
  guint8 expected_output[] = {
    0x50,                               /* push rax  */
    0x48, 0x8d, 0xa4, 0x24,             /* lea rsp, [rsp - 128] */
          0x80, 0xff, 0xff, 0xff,
    0x50,                               /* push rax  */

    0x48, 0xb8,                         /* mov rax, <rip> */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0x48, 0x8b, 0x80,                   /* mov rax, [rax + <imm32>] */
    0x01, 0x02, 0x03, 0x04,

    0x48, 0x89, 0x84, 0x24,             /* mov [rsp + 8 + 128], rax */
          0x88, 0x00, 0x00, 0x00,
    0x58,                               /* pop rax */
    0x48, 0x8d, 0xa4, 0x24,             /* lea rsp, [rsp + 128] */
          0x80, 0x00, 0x00, 0x00
  };

  *((gpointer *) (expected_output + 12)) = (gpointer) (input + 6);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_UNIX);
  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

RELOCATOR_TESTCASE (rip_relative_cmpxchg)
{
  const guint8 input[] = {
    0xf0, 0x48, 0x0f, 0xb1, 0x0d,       /* lock cmpxchg [rip + 1], rcx */
          0x01, 0x00, 0x00, 0x00
  };
  guint8 expected_output[] = {
    0x52,                               /* push rdx           */
    0x48, 0xba, 0xff, 0xff, 0xff, 0xff, /* mov rdx, <rip>     */
                0xff, 0xff, 0xff, 0xff,
    0xf0, 0x48, 0x0f, 0xb1, 0x8a,       /* lock cmpxchg [rdx + 1], rcx */
                0x01, 0x00, 0x00, 0x00,
    0x5a                                /* pop rdx            */
  };

  *((gpointer *) (expected_output + 3)) = (gpointer) (input + 9);

  gum_x86_writer_set_target_abi (&fixture->cw, GUM_ABI_WINDOWS);
  SETUP_RELOCATOR_WITH (input);

  gum_x86_relocator_read_one (&fixture->rl, NULL);
  gum_x86_relocator_write_one (&fixture->rl);
  assert_output_equals (expected_output);
}

#endif
