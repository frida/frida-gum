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
  SANITYCHECKER_TESTENTRY (three_leaked_instances)
  SANITYCHECKER_TESTENTRY (sort_instances_by_count_then_name)
TEST_LIST_END ()

SANITYCHECKER_TESTCASE (three_leaked_instances)
{
  run_simulation (fixture,
      LEAK_FIRST_PONY | LEAK_SECOND_PONY | LEAK_FIRST_ZEBRA);
  assert_same_output (fixture,
      "Instance leaks detected:\n\n"
      "\tGType\tCount\n"
      "\t-----\t-----\n"
      "\tMyPony\t2\n"
      "\tZooZebra\t1\n");
}

SANITYCHECKER_TESTCASE (sort_instances_by_count_then_name)
{
  run_simulation (fixture,
    LEAK_FIRST_PONY | LEAK_FIRST_ZEBRA | LEAK_SECOND_ZEBRA);
  assert_same_output (fixture,
      "Instance leaks detected:\n\n"
      "\tGType\tCount\n"
      "\t-----\t-----\n"
      "\tZooZebra\t2\n"
      "\tMyPony\t1\n");
}
