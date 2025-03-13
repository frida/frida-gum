/*
 * Copyright (C) 2010-2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Matt Oh <oh.jeongwook@gmail.com>
 * Copyright (C) 2024 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

#include "gum-init.h"
#include "gum/gumdarwinsymbolicator.h"

#include <mach-o/dyld.h>

#include <capstone.h>
#if defined (HAVE_I386)
# include "gumx86reader.h"
#elif defined (HAVE_ARM64)
# include "gumarm64reader.h"
#endif

#define GUM_TYPE_SYMBOL_CACHE_INVALIDATOR \
    (gum_symbol_cache_invalidator_get_type ())
G_DECLARE_FINAL_TYPE (GumSymbolCacheInvalidator,
                      gum_symbol_cache_invalidator,
                      GUM, SYMBOL_CACHE_INVALIDATOR,
                      GObject)

struct _GumSymbolCacheInvalidator
{
  GObject parent;

  GumInterceptor * interceptor;
};

static void do_deinit (void);

static GArray * gum_pointer_array_new_empty (void);
static GArray * gum_pointer_array_new_take_addresses (GumAddress * addresses,
    gsize len);

static void gum_symbol_cache_invalidator_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_symbol_cache_invalidator_dispose (GObject * object);
static void gum_symbol_cache_invalidator_stop (
    GumSymbolCacheInvalidator * self);
static void gum_symbol_cache_invalidator_on_dyld_debugger_notification (
    GumInvocationListener * self, GumInvocationContext * context);
static void gum_symbol_cache_invalidator_on_dyld_runtime_notification (
    const struct mach_header * mh, intptr_t vmaddr_slide);
static void gum_clear_symbolicator_object (void);

G_LOCK_DEFINE_STATIC (symbolicator);
static GumDarwinSymbolicator * symbolicator = NULL;
static GumSymbolCacheInvalidator * invalidator = NULL;
static gboolean invalidator_initialized = FALSE;

G_DEFINE_TYPE_EXTENDED (GumSymbolCacheInvalidator,
                        gum_symbol_cache_invalidator,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_symbol_cache_invalidator_iface_init))

static GumDarwinSymbolicator *
gum_try_obtain_symbolicator (void)
{
  GumDarwinSymbolicator * result = NULL;

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

  invalidator_initialized = TRUE;

  return result;
}

static void
do_deinit (void)
{
  G_LOCK (symbolicator);

  g_clear_object (&symbolicator);

  gum_symbol_cache_invalidator_stop (invalidator);
  g_clear_object (&invalidator);

  invalidator_initialized = FALSE;

  G_UNLOCK (symbolicator);
}

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

  g_object_unref (symbolicator);

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

  g_object_unref (symbolicator);

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

  g_object_unref (symbolicator);

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

  g_object_unref (symbolicator);

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

  g_object_unref (symbolicator);

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
  static gsize registered = FALSE;

  if (gum_process_get_teardown_requirement () == GUM_TEARDOWN_REQUIREMENT_FULL)
  {
    GumDarwinAllImageInfos infos;
    G_GNUC_UNUSED gconstpointer notification_impl;
    G_GNUC_UNUSED cs_insn * first_instruction;
    gsize offset = 0;

    if (!gum_darwin_query_all_image_infos (mach_task_self (), &infos))
      return;

    notification_impl = GSIZE_TO_POINTER (
        gum_strip_code_address (infos.notification_address));

#if defined (HAVE_I386)
    first_instruction =
        gum_x86_reader_disassemble_instruction_at (notification_impl);
    if (first_instruction != NULL && first_instruction->id == X86_INS_INT3)
      offset = first_instruction->size;
#elif defined (HAVE_ARM64)
    first_instruction =
        gum_arm64_reader_disassemble_instruction_at (notification_impl);
    if (first_instruction != NULL && first_instruction->id == ARM64_INS_BRK)
      offset = first_instruction->size;
#endif

    self->interceptor = gum_interceptor_obtain ();

    gum_interceptor_attach (self->interceptor,
        (gpointer) (notification_impl + offset),
        GUM_INVOCATION_LISTENER (self), NULL,
        GUM_ATTACH_FLAGS_UNIGNORABLE);
  }
  else if (g_once_init_enter (&registered))
  {
    _dyld_register_func_for_add_image (
        gum_symbol_cache_invalidator_on_dyld_runtime_notification);
    _dyld_register_func_for_remove_image (
        gum_symbol_cache_invalidator_on_dyld_runtime_notification);

    g_once_init_leave (&registered, TRUE);
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
  gum_clear_symbolicator_object ();
}

static void
gum_symbol_cache_invalidator_on_dyld_runtime_notification (
    const struct mach_header * mh,
    intptr_t vmaddr_slide)
{
  if (!invalidator_initialized)
    return;

  gum_clear_symbolicator_object ();
}

static void
gum_clear_symbolicator_object (void)
{
  G_LOCK (symbolicator);

  g_clear_object (&symbolicator);

  G_UNLOCK (symbolicator);
}
