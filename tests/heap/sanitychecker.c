/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "sanitychecker-fixture.c"

TEST_LIST_BEGIN (sanitychecker)
  SANITYCHECKER_TESTENTRY (no_leaks)
  SANITYCHECKER_TESTENTRY (three_leaked_instances)
  SANITYCHECKER_TESTENTRY (three_leaked_blocks)
TEST_LIST_END ()

SANITYCHECKER_TESTCASE (no_leaks)
{
  run_simulation (fixture, 0);
  g_assert (fixture->run_returned_true);
  g_assert_cmpuint (fixture->output_call_count, ==, 0);
}

SANITYCHECKER_TESTCASE (three_leaked_instances)
{
  run_simulation (fixture,
      LEAK_FIRST_PONY | LEAK_SECOND_PONY | LEAK_FIRST_ZEBRA);
  g_assert (!fixture->run_returned_true);
  g_assert_cmpuint (fixture->output_call_count, >, 0);
  assert_same_output (fixture,
      "Instance leaks detected:\n"
      "\n"
      "\tCount\tGType\n"
      "\t-----\t-----\n"
      "\t2\tMyPony\n"
      "\t1\tZooZebra\n"
      "\n"
      "\tAddress\t\tRefCount\tGType\n"
      "\t--------\t--------\t-----\n"
      "\t%p\t2\t\tMyPony\n"
      "\t%p\t1\t\tMyPony\n"
      "\t%p\t1\t\tZooZebra\n",
      fixture->second_pony, fixture->first_pony, fixture->first_zebra);
}

SANITYCHECKER_TESTCASE (three_leaked_blocks)
{
  run_simulation (fixture,
      LEAK_FIRST_BLOCK | LEAK_SECOND_BLOCK | LEAK_THIRD_BLOCK);
  g_assert (!fixture->run_returned_true);
  g_assert_cmpuint (fixture->output_call_count, >, 0);
  assert_same_output (fixture,
      "Block leaks detected:\n"
      "\n"
      "\tAddress\t\tSize\n"
      "\t--------\t----\n"
      "\t%p\t15\n"
      "\t%p\t10\n"
      "\t%p\t5\n",
      fixture->third_block,
      fixture->second_block,
      fixture->first_block);
}
