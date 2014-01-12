/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumsymbolutil.h"

#include "gumsymbolutil-priv.h"

#import <Foundation/Foundation.h>
#import "VMUSymbolicator.h"

#define GUM_POOL_ALLOC() \
  NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init]
#define GUM_POOL_RELEASE() \
  [pool release]

static gboolean gum_symbol_is_function (VMUSymbol * symbol);
static const char * gum_symbol_name_from_darwin (const char * s);

static VMUSymbolicator * symbolicator = nil;

void
_gum_symbol_util_init (void)
{
  GUM_POOL_ALLOC ();
  symbolicator = [[VMUSymbolicator symbolicatorForTask: mach_task_self ()] retain];
  GUM_POOL_RELEASE ();
}

void
_gum_symbol_util_deinit (void)
{
  GUM_POOL_ALLOC ();
  [symbolicator release];
  symbolicator = nil;
  GUM_POOL_RELEASE ();
}

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumSymbolDetails * details)
{
  gboolean result = FALSE;
  VMUSymbol * symbol;

  GUM_POOL_ALLOC ();

  symbol = [symbolicator symbolForAddress:GPOINTER_TO_SIZE (address)];
  if (symbol != nil)
  {
    VMUSourceInfo * info = nil;

    details->address = GUM_ADDRESS (address);
    strcpy (details->module_name, [[[symbol owner] name] UTF8String]);
    strcpy (details->symbol_name,
        gum_symbol_name_from_darwin ([[symbol name] UTF8String]));

    result = TRUE;

    info = [symbol sourceInfoForAddress:GPOINTER_TO_SIZE (address)];
    if (info != nil)
    {
      strcpy (details->file_name, [[info fileName] UTF8String]);
      details->line_number = [info lineNumber];
    }
    else
    {
      strcpy (details->file_name, "<unknown>");
      details->line_number = 0;
    }
  }

  GUM_POOL_RELEASE ();

  return result;
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  gchar * result = NULL;
  VMUSymbol * symbol;

  GUM_POOL_ALLOC ();

  symbol = [symbolicator symbolForAddress:GPOINTER_TO_SIZE (address)];
  if (symbol != nil)
  {
    result =
        g_strdup (gum_symbol_name_from_darwin ([[symbol name] UTF8String]));
  }

  GUM_POOL_RELEASE ();

  return result;
}

gpointer
gum_find_function (const gchar * name)
{
  gpointer result = NULL;
  NSArray * symbols;
  NSUInteger i;

  GUM_POOL_ALLOC ();

  symbols = [symbolicator symbolsForName:
      [@"_" stringByAppendingString:[NSString stringWithUTF8String:name]]];
  for (i = 0; i != [symbols count]; i++)
  {
    VMUSymbol * symbol = [symbols objectAtIndex:i];

    if (gum_symbol_is_function (symbol))
    {
      result = GSIZE_TO_POINTER ([symbol addressRange].location);
      break;
    }
  }

  GUM_POOL_RELEASE ();

  return result;
}

GArray *
gum_find_functions_named (const gchar * name)
{
  GArray * result;
  NSArray * symbols;
  NSUInteger i;

  GUM_POOL_ALLOC ();

  result = g_array_new (FALSE, FALSE, sizeof (gpointer));

  symbols = [symbolicator symbolsForName:[NSString stringWithUTF8String:name]];
  for (i = 0; i != [symbols count]; i++)
  {
    VMUSymbol * symbol = [symbols objectAtIndex:i];

    if (gum_symbol_is_function (symbol))
    {
      gpointer address = GSIZE_TO_POINTER ([symbol addressRange].location);

      g_array_append_val (result, address);
    }
  }

  GUM_POOL_RELEASE ();

  return result;
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  GArray * result;
  GPatternSpec * pspec;
  NSArray * symbols;
  NSUInteger count, i;

  GUM_POOL_ALLOC ();

  result = g_array_new (FALSE, FALSE, sizeof (gpointer));

  pspec = g_pattern_spec_new (str);

  symbols = [symbolicator symbols];
  count = [symbols count];
  for (i = 0; i != count; i++)
  {
    VMUSymbol * symbol = [symbols objectAtIndex:i];

    if (gum_symbol_is_function (symbol))
    {
      const gchar * name;

      name = gum_symbol_name_from_darwin ([[symbol name] UTF8String]);

      if (g_pattern_match_string (pspec, name))
      {
        gpointer address = GSIZE_TO_POINTER ([symbol addressRange].location);

        g_array_append_val (result, address);
      }
    }
  }

  g_pattern_spec_free (pspec);

  GUM_POOL_RELEASE ();

  return result;
}

static gboolean
gum_symbol_is_function (VMUSymbol * symbol)
{
  return ([symbol isFunction] || [symbol isObjcMethod] ||
      [symbol isJavaMethod]);
}

static const char *
gum_symbol_name_from_darwin (const char * s)
{
  return (s[0] == '_') ? s + 1 : s;
}
