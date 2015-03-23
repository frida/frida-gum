/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

#include "gum-init.h"

#include <dlfcn.h>
#import <Foundation/Foundation.h>
#include <objc/runtime.h>
#import "VMUSymbolicator.h"

#define GUM_POOL_ALLOC() \
  NSAutoreleasePool * pool = [[gum_ns_autorelease_pool alloc] init]
#define GUM_POOL_RELEASE() \
  [pool release]

static gpointer do_init (gpointer data);
static void do_deinit (void);

static gboolean gum_symbol_is_function (VMUSymbol * symbol);
static const char * gum_symbol_name_from_darwin (const char * s);

static void * gum_foundation;
static void * gum_symbolication;
static Class gum_ns_autorelease_pool;
static Class gum_ns_string;

static VMUSymbolicator *
gum_symbol_util_try_get_symbolicator (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, do_init, NULL);

  return init_once.retval;
}

static gpointer
do_init (gpointer data)
{
  void * cf;
  id symbolicator_class;
  VMUSymbolicator * symbolicator;

  cf = dlopen ("/System/Library/Frameworks/"
      "CoreFoundation.framework/CoreFoundation",
      RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD);
  if (cf == NULL)
    return NULL;
  dlclose (cf);

  gum_foundation = dlopen ("/System/Library/Frameworks/"
      "Foundation.framework/Foundation",
      RTLD_LAZY | RTLD_GLOBAL);
  if (gum_foundation == NULL)
    goto api_error;

  gum_ns_autorelease_pool = objc_getClass ("NSAutoreleasePool");
  g_assert (gum_ns_autorelease_pool != nil);
  gum_ns_string = objc_getClass ("NSString");
  g_assert (gum_ns_string != nil);

  gum_symbolication = dlopen ("/System/Library/PrivateFrameworks/"
      "Symbolication.framework/Symbolication",
      RTLD_LAZY | RTLD_GLOBAL);
  if (gum_symbolication == NULL)
    goto api_error;

  symbolicator_class = objc_getClass ("VMUSymbolicator");
  if (symbolicator_class == NULL)
    goto api_error;

  GUM_POOL_ALLOC ();
  symbolicator =
      [[symbolicator_class symbolicatorForTask: mach_task_self ()] retain];
  g_print ("created symbolicator %p\n", symbolicator);
  GUM_POOL_RELEASE ();

  _gum_register_destructor (do_deinit);

  return symbolicator;

api_error:
  {
    if (gum_symbolication != NULL)
    {
      dlclose (gum_symbolication);
      gum_symbolication = NULL;
    }

    if (gum_foundation != NULL)
    {
      dlclose (gum_foundation);
      gum_foundation = NULL;
    }

    return NULL;
  }
}

static void
do_deinit (void)
{
  VMUSymbolicator * symbolicator;

  GUM_POOL_ALLOC ();

  symbolicator = gum_symbol_util_try_get_symbolicator ();
  g_assert (symbolicator != nil);
  [symbolicator release];
  symbolicator = nil;

  dlclose (gum_symbolication);
  gum_symbolication = NULL;

  gum_ns_string = nil;
  gum_ns_autorelease_pool = nil;

  dlclose (gum_foundation);
  gum_foundation = NULL;

  GUM_POOL_RELEASE ();
}

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumSymbolDetails * details)
{
  VMUSymbolicator * symbolicator;
  gboolean result = FALSE;
  VMUSymbol * symbol;

  symbolicator = gum_symbol_util_try_get_symbolicator ();
  if (symbolicator == nil)
    return FALSE;

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
      details->file_name = '\0';
      details->line_number = 0;
    }
  }

  GUM_POOL_RELEASE ();

  return result;
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  VMUSymbolicator * symbolicator;
  gchar * result = NULL;
  VMUSymbol * symbol;

  symbolicator = gum_symbol_util_try_get_symbolicator ();
  if (symbolicator == nil)
    return NULL;

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
  VMUSymbolicator * symbolicator;
  gpointer result = NULL;
  NSString * underscore;
  NSArray * symbols;
  NSUInteger i;

  symbolicator = gum_symbol_util_try_get_symbolicator ();
  if (symbolicator == nil)
    return NULL;

  GUM_POOL_ALLOC ();

  underscore = [gum_ns_string stringWithUTF8String:"_"];
  symbols = [symbolicator symbolsForName:[underscore stringByAppendingString:
      [gum_ns_string stringWithUTF8String:name]]];
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
  VMUSymbolicator * symbolicator;
  NSArray * symbols;
  NSUInteger i;

  result = g_array_new (FALSE, FALSE, sizeof (gpointer));

  symbolicator = gum_symbol_util_try_get_symbolicator ();
  if (symbolicator == nil)
    return result;

  GUM_POOL_ALLOC ();

  symbols =
      [symbolicator symbolsForName:[gum_ns_string stringWithUTF8String:name]];
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
  VMUSymbolicator * symbolicator;
  GArray * result;
  GPatternSpec * pspec;
  NSArray * symbols;
  NSUInteger count, i;

  result = g_array_new (FALSE, FALSE, sizeof (gpointer));

  symbolicator = gum_symbol_util_try_get_symbolicator ();
  if (symbolicator == nil)
    return result;

  GUM_POOL_ALLOC ();

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
