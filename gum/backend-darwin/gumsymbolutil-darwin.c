/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Matt Oh <oh.jeongwook@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

#include "gum-init.h"
#include "gumdarwinsymbolicator.h"

#include <mach-o/dyld.h>

#ifndef GUM_DIET
# define GUM_TYPE_SYMBOL_CACHE_INVALIDATOR \
    (gum_symbol_cache_invalidator_get_type ())
GUM_DECLARE_FINAL_TYPE (GumSymbolCacheInvalidator, gum_symbol_cache_invalidator,
    GUM, SYMBOL_CACHE_INVALIDATOR, GObject)

struct _GumSymbolCacheInvalidator
{
  GObject parent;

  GumInterceptor * interceptor;
};

static void do_deinit (void);
#endif

static GArray * gum_pointer_array_new_empty (void);
static GArray * gum_pointer_array_new_take_addresses (GumAddress * addresses,
    gsize len);

#ifndef GUM_DIET
static void gum_symbol_cache_invalidator_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_symbol_cache_invalidator_dispose (GObject * object);
static void gum_symbol_cache_invalidator_stop (
    GumSymbolCacheInvalidator * self);
static void gum_symbol_cache_invalidator_on_dyld_debugger_notification (
    GumInvocationListener * self, GumInvocationContext * context);

G_LOCK_DEFINE_STATIC (symbolicator);
static GumDarwinSymbolicator * symbolicator = NULL;
static GumSymbolCacheInvalidator * invalidator = NULL;

G_DEFINE_TYPE_EXTENDED (GumSymbolCacheInvalidator,
                        gum_symbol_cache_invalidator,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_symbol_cache_invalidator_iface_init))
#endif

static GumDarwinSymbolicator *
gum_try_obtain_symbolicator (void)
{
  GumDarwinSymbolicator * result = NULL;

#ifndef GUM_DIET
  G_LOCK (symbolicator);

  if (symbolicator == NULL)
  {
    symbolicator =
        gum_darwin_symbolicator_new_with_task (mach_task_self (), NULL);
  }

  if (invalidator == NULL)
  {
    invalidator = g_object_new (GUM_TYPE_SYMBOL_CACHE_INVALIDATOR, NULL);

    _gum_register_early_destructor (do_deinit);
  }

  if (symbolicator != NULL)
    result = g_object_ref (symbolicator);

  G_UNLOCK (symbolicator);
#endif

  return result;
}

#ifndef GUM_DIET

static void
do_deinit (void)
{
  G_LOCK (symbolicator);

  g_clear_object (&symbolicator);

  gum_symbol_cache_invalidator_stop (invalidator);
  g_clear_object (&invalidator);

  G_UNLOCK (symbolicator);
}

#endif

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumDebugSymbolDetails * details)
{
  gboolean success;
  GumDarwinSymbolicator * symbolicator;

  if ((symbolicator = gum_try_obtain_symbolicator ()) == NULL)
    return FALSE;

  success = gum_darwin_symbolicator_details_from_address (symbolicator,
      GUM_ADDRESS (address), details);

  gum_object_unref (symbolicator);

  return success;
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  gchar * name;
  GumDarwinSymbolicator * symbolicator;

  if ((symbolicator = gum_try_obtain_symbolicator ()) == NULL)
    return NULL;

  name = gum_darwin_symbolicator_name_from_address (symbolicator,
      GUM_ADDRESS (address));

  gum_object_unref (symbolicator);

  return name;
}

gpointer
gum_find_function (const gchar * name)
{
  gpointer address;
  GumDarwinSymbolicator * symbolicator;

  if ((symbolicator = gum_try_obtain_symbolicator ()) == NULL)
    return NULL;

  address = GSIZE_TO_POINTER (
      gum_darwin_symbolicator_find_function (symbolicator, name));

  gum_object_unref (symbolicator);

  return address;
}

GArray *
gum_find_functions_named (const gchar * name)
{
  GumDarwinSymbolicator * symbolicator;
  GumAddress * addresses;
  gsize len;

  if ((symbolicator = gum_try_obtain_symbolicator ()) == NULL)
    return gum_pointer_array_new_empty ();

  addresses =
      gum_darwin_symbolicator_find_functions_named (symbolicator, name, &len);

  gum_object_unref (symbolicator);

  return gum_pointer_array_new_take_addresses (addresses, len);
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  GumDarwinSymbolicator * symbolicator;
  GumAddress * addresses;
  gsize len;

  if ((symbolicator = gum_try_obtain_symbolicator ()) == NULL)
    return gum_pointer_array_new_empty ();

  addresses =
      gum_darwin_symbolicator_find_functions_matching (symbolicator, str, &len);

  gum_object_unref (symbolicator);

  return gum_pointer_array_new_take_addresses (addresses, len);
}

gboolean
gum_load_symbols (const gchar * path)
{
  return FALSE;
}

static GArray *
gum_pointer_array_new_empty (void)
{
  return g_array_new (FALSE, FALSE, sizeof (gpointer));
}

static GArray *
gum_pointer_array_new_take_addresses (GumAddress * addresses,
                                      gsize len)
{
  GArray * result;
  gsize i;

  result = g_array_sized_new (FALSE, FALSE, sizeof (gpointer), len);

  for (i = 0; i != len; i++)
  {
    gpointer address = GSIZE_TO_POINTER (addresses[i]);
    g_array_append_val (result, address);
  }

  g_free (addresses);

  return result;
}

#ifndef GUM_DIET

static void
gum_symbol_cache_invalidator_class_init (GumSymbolCacheInvalidatorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_symbol_cache_invalidator_dispose;

  (void) GUM_IS_SYMBOL_CACHE_INVALIDATOR;
  (void) GUM_SYMBOL_CACHE_INVALIDATOR;
  (void) glib_autoptr_cleanup_GumSymbolCacheInvalidator;
}

static void
gum_symbol_cache_invalidator_iface_init (gpointer g_iface,
                                         gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_symbol_cache_invalidator_on_dyld_debugger_notification;
}

static void
gum_symbol_cache_invalidator_init (GumSymbolCacheInvalidator * self)
{
  GumDarwinAllImageInfos infos;

  self->interceptor = gum_interceptor_obtain ();

  if (gum_darwin_query_all_image_infos (mach_task_self (), &infos))
  {
    gum_interceptor_attach (self->interceptor,
        GSIZE_TO_POINTER (infos.notification_address),
        GUM_INVOCATION_LISTENER (self), NULL);
  }
}

static void
gum_symbol_cache_invalidator_dispose (GObject * object)
{
  GumSymbolCacheInvalidator * self = GUM_SYMBOL_CACHE_INVALIDATOR (object);

  g_clear_object (&self->interceptor);

  G_OBJECT_CLASS (gum_symbol_cache_invalidator_parent_class)->dispose (object);
}

static void
gum_symbol_cache_invalidator_stop (GumSymbolCacheInvalidator * self)
{
  gum_interceptor_detach (self->interceptor, GUM_INVOCATION_LISTENER (self));
}

static void
gum_symbol_cache_invalidator_on_dyld_debugger_notification (
    GumInvocationListener * self,
    GumInvocationContext * context)
{
  G_LOCK (symbolicator);

  g_clear_object (&symbolicator);

  G_UNLOCK (symbolicator);
}

#endif
