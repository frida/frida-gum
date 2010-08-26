/*
 * Copyright (C) 2009-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumx86functionparser.h"

#include "testutil.h"

#ifdef G_OS_WIN32
#define VC_EXTRALEAN
#include <windows.h>
#endif

#define FUNCPARSER_TESTCASE(NAME) \
    void test_function_parser_ ## NAME ( \
        TestFunctionParserFixture * fixture, gconstpointer data)
#define FUNCPARSER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/FunctionParser", test_function_parser, \
        NAME, TestFunctionParserFixture)

typedef struct _TestFunctionParserFixture
{
  GumX86FunctionParser fp;
} TestFunctionParserFixture;

static void
test_function_parser_fixture_setup (TestFunctionParserFixture * fixture,
                                    gconstpointer data)
{
  gum_x86_function_parser_init (&fixture->fp);
}

static void
test_function_parser_fixture_teardown (TestFunctionParserFixture * fixture,
                                       gconstpointer data)
{
}
