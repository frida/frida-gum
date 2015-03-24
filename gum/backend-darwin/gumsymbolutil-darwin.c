/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

#include "gum-init.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <mach/mach.h>

#define kCSNull ((CSTypeRef) { NULL, NULL })
#define kCSNow  G_GUINT64_CONSTANT (0x80000000)

typedef struct _CSTypeRef CSTypeRef;
typedef struct _CSRange CSRange;
typedef uint64_t CSTime;

typedef CSTypeRef CSSymbolicatorRef;
typedef CSTypeRef CSSymbolRef;
typedef CSTypeRef CSSymbolOwnerRef;
typedef CSTypeRef CSSourceInfoRef;

typedef int (^ CSEachSymbolBlock) (CSSymbolRef symbol);

struct _CSTypeRef
{
  void * data;
  void * obj;
};

struct _CSRange
{
  uint64_t location;
  uint64_t length;
};

static gpointer do_init (gpointer data);
static void do_deinit (void);

static void * gum_cf;
static void * gum_cs;

static CSSymbolicatorRef gum_symbolicator;

#define GUM_DECLARE_CS_FUNC(N, R, A) \
    typedef R (* G_PASTE (G_PASTE (CS, N), Func)) A; \
    static G_PASTE (G_PASTE (CS, N), Func) G_PASTE (CS, N)

GUM_DECLARE_CS_FUNC (IsNull, Boolean, (CSTypeRef cs));
GUM_DECLARE_CS_FUNC (Retain, CSTypeRef, (CSTypeRef cs));
GUM_DECLARE_CS_FUNC (Release, void, (CSTypeRef cs));
GUM_DECLARE_CS_FUNC (GetRetainCount, CFIndex, (CSTypeRef cs));
GUM_DECLARE_CS_FUNC (Show, void, (CSTypeRef cs));

GUM_DECLARE_CS_FUNC (SymbolicatorCreateWithTask, CSSymbolicatorRef,
    (task_t task));
GUM_DECLARE_CS_FUNC (SymbolicatorGetSymbolWithAddressAtTime, CSSymbolRef,
    (CSSymbolicatorRef symbolicator, mach_vm_address_t address, CSTime time));
GUM_DECLARE_CS_FUNC (SymbolicatorGetSourceInfoWithAddressAtTime,
    CSSourceInfoRef, (CSSymbolicatorRef symbolicator, mach_vm_address_t address,
    CSTime time));
GUM_DECLARE_CS_FUNC (SymbolicatorForeachSymbolAtTime, int,
    (CSSymbolicatorRef symbolicator, CSTime time, CSEachSymbolBlock block));
GUM_DECLARE_CS_FUNC (SymbolicatorForeachSymbolWithNameAtTime, int,
    (CSSymbolicatorRef symbolicator, const char * name, CSTime time,
    CSEachSymbolBlock block));

GUM_DECLARE_CS_FUNC (SymbolGetName, const char *, (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolGetRange, CSRange, (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolGetSymbolOwner, CSSymbolOwnerRef,
    (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolIsFunction, Boolean, (CSSymbolRef symbol));

GUM_DECLARE_CS_FUNC (SymbolOwnerGetName, const char *,
    (CSSymbolOwnerRef owner));

GUM_DECLARE_CS_FUNC (SourceInfoGetFilename, const char *,
    (CSSourceInfoRef info));
GUM_DECLARE_CS_FUNC (SourceInfoGetLineNumber, int,
    (CSSourceInfoRef info));

#undef GUM_DECLARE_CS_FUNC

static gboolean
gum_symbol_util_try_init (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, do_init, NULL);

  return GPOINTER_TO_SIZE (init_once.retval);
}

static gpointer
do_init (gpointer data)
{
  /*
   * CoreFoundation must be loaded by the main thread, so we should avoid
   * loading it. This must be done by the user of frida-gum explicitly.
   */
  gum_cf = dlopen ("/System/Library/Frameworks/"
      "CoreFoundation.framework/CoreFoundation",
      RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD);
  if (gum_cf == NULL)
    return NULL;

  gum_cs = dlopen ("/System/Library/PrivateFrameworks/"
      "CoreSymbolication.framework/CoreSymbolication",
      RTLD_LAZY | RTLD_GLOBAL);
  if (gum_cs == NULL)
    goto api_error;

#define GUM_TRY_ASSIGN_CS_FUNC(N) \
  G_PASTE (CS, N) = dlsym (gum_cs, G_STRINGIFY (G_PASTE (CS, N))); \
  if (G_PASTE (CS, N) == NULL) \
  { \
    g_print ("failed to resolve " G_STRINGIFY (N) "\n"); \
    goto api_error; \
  }

  GUM_TRY_ASSIGN_CS_FUNC (IsNull);
  GUM_TRY_ASSIGN_CS_FUNC (Retain);
  GUM_TRY_ASSIGN_CS_FUNC (Release);
  GUM_TRY_ASSIGN_CS_FUNC (GetRetainCount);
  GUM_TRY_ASSIGN_CS_FUNC (Show);

  GUM_TRY_ASSIGN_CS_FUNC (SymbolicatorCreateWithTask);
  GUM_TRY_ASSIGN_CS_FUNC (SymbolicatorGetSymbolWithAddressAtTime);
  GUM_TRY_ASSIGN_CS_FUNC (SymbolicatorGetSourceInfoWithAddressAtTime);
  GUM_TRY_ASSIGN_CS_FUNC (SymbolicatorForeachSymbolAtTime);
  GUM_TRY_ASSIGN_CS_FUNC (SymbolicatorForeachSymbolWithNameAtTime);

  GUM_TRY_ASSIGN_CS_FUNC (SymbolGetName);
  GUM_TRY_ASSIGN_CS_FUNC (SymbolGetRange);
  GUM_TRY_ASSIGN_CS_FUNC (SymbolGetSymbolOwner);
  GUM_TRY_ASSIGN_CS_FUNC (SymbolIsFunction);

  GUM_TRY_ASSIGN_CS_FUNC (SymbolOwnerGetName);

  GUM_TRY_ASSIGN_CS_FUNC (SourceInfoGetFilename);
  GUM_TRY_ASSIGN_CS_FUNC (SourceInfoGetLineNumber);

#undef GUM_TRY_ASSIGN_CS_FUNC

  gum_symbolicator = CSSymbolicatorCreateWithTask (mach_task_self ());

  _gum_register_destructor (do_deinit);

  return GSIZE_TO_POINTER (TRUE);

api_error:
  {
    if (gum_cs != NULL)
    {
      dlclose (gum_cs);
      gum_cs = NULL;
    }

    if (gum_cf != NULL)
    {
      dlclose (gum_cf);
      gum_cf = NULL;
    }

    return GSIZE_TO_POINTER (FALSE);
  }
}

static void
do_deinit (void)
{
  CSRelease (gum_symbolicator);
  gum_symbolicator = kCSNull;

  dlclose (gum_cs);
  gum_cs = NULL;

  dlclose (gum_cf);
  gum_cf = NULL;
}

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumSymbolDetails * details)
{
  gboolean success = FALSE;
  CSSymbolRef symbol;

  if (!gum_symbol_util_try_init ())
    return FALSE;

  symbol = CSSymbolicatorGetSymbolWithAddressAtTime (
      gum_symbolicator, GPOINTER_TO_SIZE (address), kCSNow);
  if (!CSIsNull (symbol))
  {
    CSSourceInfoRef info;

    details->address = GUM_ADDRESS (address);
    strcpy (details->module_name, CSSymbolOwnerGetName (
        CSSymbolGetSymbolOwner (symbol)));
    strcpy (details->symbol_name, CSSymbolGetName (symbol));

    info = CSSymbolicatorGetSourceInfoWithAddressAtTime (gum_symbolicator,
        GPOINTER_TO_SIZE (address), kCSNow);
    if (!CSIsNull (info))
    {
      strcpy (details->file_name, CSSourceInfoGetFilename (info));
      details->line_number = CSSourceInfoGetLineNumber (info);
    }
    else
    {
      details->file_name[0] = '\0';
      details->line_number = 0;
    }

    success = TRUE;
  }

  return success;
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  gchar * result = NULL;
  CSSymbolRef symbol;

  if (!gum_symbol_util_try_init ())
    return NULL;

  symbol = CSSymbolicatorGetSymbolWithAddressAtTime (
      gum_symbolicator, GPOINTER_TO_SIZE (address), kCSNow);
  if (!CSIsNull (symbol))
  {
    result = g_strdup (CSSymbolGetName (symbol));
  }

  return result;
}

gpointer
gum_find_function (const gchar * name)
{
  __block gpointer result = NULL;

  if (!gum_symbol_util_try_init ())
    return NULL;

  CSSymbolicatorForeachSymbolWithNameAtTime (gum_symbolicator, name, kCSNow,
      ^(CSSymbolRef symbol)
  {
    if (result == NULL && CSSymbolIsFunction (symbol))
      result = GSIZE_TO_POINTER (CSSymbolGetRange (symbol).location);
    return 0;
  });

  return result;
}

GArray *
gum_find_functions_named (const gchar * name)
{
  GArray * result;

  result = g_array_new (FALSE, FALSE, sizeof (gpointer));

  if (!gum_symbol_util_try_init ())
    return result;

  CSSymbolicatorForeachSymbolWithNameAtTime (gum_symbolicator, name, kCSNow,
      ^(CSSymbolRef symbol)
  {
    if (CSSymbolIsFunction (symbol))
    {
      gpointer address = GSIZE_TO_POINTER (CSSymbolGetRange (symbol).location);
      g_array_append_val (result, address);
    }
    return 0;
  });

  return result;
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  GArray * result;
  GPatternSpec * pspec;

  result = g_array_new (FALSE, FALSE, sizeof (gpointer));

  if (!gum_symbol_util_try_init ())
    return result;

  pspec = g_pattern_spec_new (str);

  CSSymbolicatorForeachSymbolAtTime (gum_symbolicator, kCSNow,
      ^(CSSymbolRef symbol)
  {
    if (CSSymbolIsFunction (symbol))
    {
      const char * name = CSSymbolGetName (symbol);
      if (name != NULL && g_pattern_match_string (pspec, name))
      {
        gpointer address = GSIZE_TO_POINTER (CSSymbolGetRange (symbol).location);
        g_array_append_val (result, address);
      }
    }
    return 0;
  });

  g_pattern_spec_free (pspec);

  return result;
}

