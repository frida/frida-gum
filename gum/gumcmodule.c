/*
 * Copyright (C) 2019-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcmodule.h"

#include "gum-init.h"
#include "gumcloak.h"
#include "guminterceptor.h"
#include "gummapper.h"
#include "gummetalarray.h"
#include "gummetalhash.h"
#include "gummodulemap.h"
#include "gumnativemoduleresolver.h"
#include "gumprocess.h"
#include "gumspinlock.h"
#include "gumstalker.h"
#include "gumtls.h"
#if defined (HAVE_I386)
# include "gumx86writer.h"
#elif defined (HAVE_ARM)
# include "gumarmwriter.h"
# include "gumthumbwriter.h"
#elif defined (HAVE_ARM64)
# include "gumarm64writer.h"
#elif defined (HAVE_MIPS)
# include "gummipswriter.h"
#endif
#ifdef HAVE_DARWIN
# include "gum/gumdarwin.h"
# include "gum/gumdarwinmoduleresolver.h"
#endif

#include <stdio.h>
#include <string.h>
#include <gio/gio.h>
#include <json-glib/json-glib.h>
#ifdef HAVE_WINDOWS
# include <windows.h>
#endif

#ifdef HAVE_TINYCC
static GumCModule * gum_tcc_cmodule_new (const gchar * source,
    const GumCModuleOptions * options, GError ** error);
#endif
#ifndef G_OS_NONE
static GumCModule * gum_external_cmodule_new (const gchar * source,
    GBytes * binary, const GumCModuleOptions * options, GError ** error);
#endif

typedef struct _GumCModulePrivate GumCModulePrivate;

typedef void (* GumCModuleInitFunc) (void);
typedef void (* GumCModuleFinalizeFunc) (void);
typedef void (* GumCModuleDestructFunc) (void);

struct _GumCModulePrivate
{
  GumMemoryRange range;
  GumCModuleFinalizeFunc finalize;
  GumCModuleDestructFunc destruct;
};

static void gum_cmodule_finalize (GObject * object);
static void gum_emit_standard_define (const GumCDefineDetails * details,
    gpointer user_data);
static void gum_cmodule_add_define (GumCModule * self, const gchar * name,
    const gchar * value);
static gboolean gum_cmodule_load (GumCModule * self, GumMemoryRange * range,
    GString ** error_messages);
static void gum_cmodule_link_post (GumCModule * self);
static void gum_cmodule_unload (GumCModule * self,
    const GumMemoryRange * range);
static void gum_emit_builtin_define (const gchar * name, const gchar * value,
    GumFoundCDefineFunc func, gpointer user_data);
static void gum_emit_builtin_define_str (const gchar * name,
    const gchar * value, GumFoundCDefineFunc func, gpointer user_data);

#ifndef G_OS_NONE
static gboolean gum_populate_include_dir (const gchar * path, GError ** error);
static void gum_rmtree (GFile * file);
static gboolean gum_call_tool (const gchar * cwd, const gchar * const * argv,
    gchar ** output, gint * exit_status, GError ** error);
# ifdef HAVE_WINDOWS
static void gum_append_quoted_argument (GString * command_line,
    const gchar * arg);
# endif
#endif
static void gum_append_error (GString ** messages, const char * msg);

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE (GumCModule, gum_cmodule, G_TYPE_OBJECT);

#include "gumcmodule-runtime.h"

static void
gum_cmodule_class_init (GumCModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_cmodule_finalize;
}

static void
gum_cmodule_init (GumCModule * cmodule)
{
}

static void
gum_cmodule_finalize (GObject * object)
{
  GumCModule * self;
  GumCModulePrivate * priv;
  const GumMemoryRange * r;

  self = GUM_CMODULE (object);
  priv = gum_cmodule_get_instance_private (self);
  r = &priv->range;

  if (r->base_address != 0)
  {
    if (priv->finalize != NULL)
      priv->finalize ();

    if (priv->destruct != NULL)
      priv->destruct ();

    gum_cloak_remove_range (r);

    gum_cmodule_unload (self, r);
  }

  gum_cmodule_drop_metadata (self);

  G_OBJECT_CLASS (gum_cmodule_parent_class)->finalize (object);
}

GumCModule *
gum_cmodule_new (const gchar * source,
                 GBytes * binary,
                 const GumCModuleOptions * options,
                 GError ** error)
{
  GumCModuleToolchain toolchain = options->toolchain;

  if (toolchain == GUM_CMODULE_TOOLCHAIN_ANY)
  {
#ifdef HAVE_TINYCC
    toolchain = GUM_CMODULE_TOOLCHAIN_INTERNAL;
#else
    toolchain = GUM_CMODULE_TOOLCHAIN_EXTERNAL;
#endif
  }

  if (binary != NULL)
    toolchain = GUM_CMODULE_TOOLCHAIN_EXTERNAL;

  switch (toolchain)
  {
    case GUM_CMODULE_TOOLCHAIN_INTERNAL:
#ifdef HAVE_TINYCC
      return gum_tcc_cmodule_new (source, options, error);
#else
      g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
          "Internal toolchain is not available in this build configuration");
      return NULL;
#endif
    case GUM_CMODULE_TOOLCHAIN_EXTERNAL:
#ifndef G_OS_NONE
      return gum_external_cmodule_new (source, binary, options, error);
#else
      g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
          "External toolchain is not supported by the Barebone backend");
      return NULL;
#endif
    default:
      g_assert_not_reached ();
  }
}

const GumMemoryRange *
gum_cmodule_get_range (GumCModule * self)
{
  GumCModulePrivate * priv = gum_cmodule_get_instance_private (self);

  return &priv->range;
}

static void
gum_cmodule_add_standard_defines (GumCModule * self)
{
  gum_cmodule_enumerate_builtin_defines (gum_emit_standard_define, self);
}

static void
gum_emit_standard_define (const GumCDefineDetails * details,
                          gpointer user_data)
{
  GumCModule * self = user_data;

  gum_cmodule_add_define (self, details->name, details->value);
}

static void
gum_cmodule_add_define (GumCModule * self,
                        const gchar * name,
                        const gchar * value)
{
  GUM_CMODULE_GET_CLASS (self)->add_define (self, name, value);
}

void
gum_cmodule_add_symbol (GumCModule * self,
                        const gchar * name,
                        gconstpointer value)
{
  GUM_CMODULE_GET_CLASS (self)->add_symbol (self, name, value);
}

gboolean
gum_cmodule_link (GumCModule * self,
                  GError ** error)
{
  gboolean success = FALSE;
  GumCModulePrivate * priv;
  GString * error_messages;
  GumMemoryRange * r;

  priv = gum_cmodule_get_instance_private (self);
  r = &priv->range;

  error_messages = NULL;
  if (gum_cmodule_load (self, r, &error_messages))
  {
    GumCModuleInitFunc init;

    gum_cloak_add_range (r);

    init = GUM_POINTER_TO_FUNCPTR (GumCModuleInitFunc,
        gum_cmodule_find_symbol_by_name (self, "init"));
    if (init != NULL)
      init ();

    priv->finalize = GUM_POINTER_TO_FUNCPTR (GumCModuleFinalizeFunc,
        gum_cmodule_find_symbol_by_name (self, "finalize"));

    success = TRUE;
  }

  gum_cmodule_link_post (self);

  if (error_messages != NULL)
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Linking failed: %s", error_messages->str);
    g_string_free (error_messages, TRUE);
  }

  return success;
}

static gboolean
gum_cmodule_load (GumCModule * self,
                  GumMemoryRange * range,
                  GString ** error_messages)
{
  return GUM_CMODULE_GET_CLASS (self)->load (self, range, error_messages);
}

static void
gum_cmodule_link_post (GumCModule * self)
{
  GUM_CMODULE_GET_CLASS (self)->link_post (self);
}

static void
gum_cmodule_unload (GumCModule * self,
                    const GumMemoryRange * range)
{
  GUM_CMODULE_GET_CLASS (self)->unload (self, range);
}

void
gum_cmodule_enumerate_builtin_defines (GumFoundCDefineFunc func,
                                       gpointer user_data)
{
#if defined (HAVE_I386)
  gum_emit_builtin_define ("HAVE_I386", NULL, func, user_data);
#elif defined (HAVE_ARM)
  gum_emit_builtin_define ("HAVE_ARM", NULL, func, user_data);
#elif defined (HAVE_ARM64)
  gum_emit_builtin_define ("HAVE_ARM64", NULL, func, user_data);
#elif defined (HAVE_MIPS)
  gum_emit_builtin_define ("HAVE_MIPS", NULL, func, user_data);
#endif

  gum_emit_builtin_define_str ("G_GINT16_MODIFIER", G_GINT16_MODIFIER,
      func, user_data);
  gum_emit_builtin_define_str ("G_GINT32_MODIFIER", G_GINT32_MODIFIER,
      func, user_data);
  gum_emit_builtin_define_str ("G_GINT64_MODIFIER", G_GINT64_MODIFIER,
      func, user_data);
  gum_emit_builtin_define_str ("G_GSIZE_MODIFIER", G_GSIZE_MODIFIER,
      func, user_data);
  gum_emit_builtin_define_str ("G_GSSIZE_MODIFIER", G_GSSIZE_MODIFIER,
      func, user_data);

  gum_emit_builtin_define ("GLIB_SIZEOF_VOID_P",
      G_STRINGIFY (GLIB_SIZEOF_VOID_P), func, user_data);
}

static void
gum_emit_builtin_define (const gchar * name,
                         const gchar * value,
                         GumFoundCDefineFunc func,
                         gpointer user_data)
{
  GumCDefineDetails d = { name, value };

  func (&d, user_data);
}

static void
gum_emit_builtin_define_str (const gchar * name,
                             const gchar * value,
                             GumFoundCDefineFunc func,
                             gpointer user_data)
{
  gchar * raw_value;

  raw_value = g_strconcat ("\"", value, "\"", NULL);

  gum_emit_builtin_define (name, raw_value, func, user_data);

  g_free (raw_value);
}

void
gum_cmodule_enumerate_builtin_headers (GumFoundCHeaderFunc func,
                                       gpointer user_data)
{
  guint i;

  for (i = 0; i != G_N_ELEMENTS (gum_cmodule_headers); i++)
  {
    const GumCHeaderDetails * h = &gum_cmodule_headers[i];

    func (h, user_data);
  }
}

void
gum_cmodule_enumerate_symbols (GumCModule * self,
                               GumFoundCSymbolFunc func,
                               gpointer user_data)
{
  GUM_CMODULE_GET_CLASS (self)->enumerate_symbols (self, func, user_data);
}

gpointer
gum_cmodule_find_symbol_by_name (GumCModule * self,
                                 const gchar * name)
{
  return GUM_CMODULE_GET_CLASS (self)->find_symbol_by_name (self, name);
}

void
gum_cmodule_drop_metadata (GumCModule * self)
{
  GUM_CMODULE_GET_CLASS (self)->drop_metadata (self);
}

#ifdef HAVE_TINYCC

#include <libtcc.h>

#define GUM_TYPE_TCC_CMODULE (gum_tcc_cmodule_get_type ())
G_DECLARE_FINAL_TYPE (GumTccCModule, gum_tcc_cmodule, GUM, TCC_CMODULE,
    GumCModule)

typedef struct _GumTccApplyContext GumTccApplyContext;
typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;

struct _GumTccCModule
{
  GumCModule parent;

  TCCState * state;
  gsize size;
};

struct _GumTccApplyContext
{
  GumTccCModule * module;
  gpointer executable_base;
  gboolean success;
};

struct _GumEnumerateSymbolsContext
{
  GumFoundCSymbolFunc func;
  gpointer user_data;
};

static void gum_tcc_cmodule_add_define (GumCModule * cm, const gchar * name,
    const gchar * value);
static void gum_tcc_cmodule_add_symbol (GumCModule * cm, const gchar * name,
    gconstpointer value);
static gboolean gum_tcc_cmodule_load (GumCModule * cm, GumMemoryRange * range,
    GString ** error_messages);
static gboolean gum_tcc_cmodule_relocate (GumTccCModule * self, gpointer base);
static void gum_tcc_cmodule_relocate_views (gpointer writable_base,
    gpointer user_data);
static void gum_tcc_cmodule_link_post (GumCModule * cm);
static void gum_tcc_cmodule_unload (GumCModule * cm,
    const GumMemoryRange * range);
static void gum_tcc_cmodule_enumerate_symbols (GumCModule * cm,
    GumFoundCSymbolFunc func, gpointer user_data);
static gpointer gum_tcc_cmodule_find_symbol_by_name (GumCModule * cm,
    const gchar * name);
static void gum_tcc_cmodule_drop_metadata (GumCModule * cm);
static void gum_emit_symbol (void * ctx, const char * name, const void * val);
static void gum_append_tcc_error (void * opaque, const char * msg);
static void gum_emit_symbol (void * ctx, const char * name, const void * val);
static const char * gum_tcc_cmodule_load_header (void * opaque,
    const char * path, int * len);
static void * gum_tcc_cmodule_resolve_symbol (void * opaque, const char * name);

static void gum_add_abi_symbols (TCCState * state);
static const gchar * gum_undecorate_name (const gchar * name);

G_DEFINE_TYPE (GumTccCModule, gum_tcc_cmodule, GUM_TYPE_CMODULE)

static void
gum_tcc_cmodule_class_init (GumTccCModuleClass * klass)
{
  GumCModuleClass * cmodule_class = GUM_CMODULE_CLASS (klass);

  cmodule_class->add_define = gum_tcc_cmodule_add_define;
  cmodule_class->add_symbol = gum_tcc_cmodule_add_symbol;
  cmodule_class->load = gum_tcc_cmodule_load;
  cmodule_class->link_post = gum_tcc_cmodule_link_post;
  cmodule_class->unload = gum_tcc_cmodule_unload;
  cmodule_class->enumerate_symbols = gum_tcc_cmodule_enumerate_symbols;
  cmodule_class->find_symbol_by_name = gum_tcc_cmodule_find_symbol_by_name;
  cmodule_class->drop_metadata = gum_tcc_cmodule_drop_metadata;
}

static void
gum_tcc_cmodule_init (GumTccCModule * cmodule)
{
}

static GumCModule *
gum_tcc_cmodule_new (const gchar * source,
                     const GumCModuleOptions * options,
                     GError ** error)
{
  GumCModule * result;
  GumTccCModule * cmodule;
  TCCState * state;
  GString * error_messages;
  gchar * combined_source;

  result = g_object_new (GUM_TYPE_TCC_CMODULE, NULL);
  cmodule = GUM_TCC_CMODULE (result);

  state = tcc_new ();
  cmodule->state = state;

  error_messages = NULL;
  tcc_set_error_func (state, &error_messages, gum_append_tcc_error);

  tcc_set_cpp_load_func (state, cmodule, gum_tcc_cmodule_load_header);
  tcc_set_linker_resolve_func (state, cmodule, gum_tcc_cmodule_resolve_symbol);
  tcc_set_options (state,
      "-Wall "
      "-Werror "
      "-isystem /frida "
      "-isystem /frida/capstone "
      "-nostdinc "
      "-nostdlib"
  );

  gum_cmodule_add_standard_defines (result);
#ifdef HAVE_WINDOWS
  gum_cmodule_add_define (result, "extern", "__attribute__ ((dllimport))");
#endif

  tcc_set_output_type (state, TCC_OUTPUT_MEMORY);

  combined_source = g_strconcat ("#line 1 \"module.c\"\n", source, NULL);

  tcc_compile_string (state, combined_source);

  g_free (combined_source);

  tcc_set_error_func (state, NULL, NULL);

  if (error_messages != NULL)
    goto propagate_error;

  gum_add_abi_symbols (state);

  return result;

propagate_error:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Compilation failed: %s", error_messages->str);
    g_string_free (error_messages, TRUE);

    g_object_unref (result);

    return NULL;
  }
}

static void
gum_tcc_cmodule_add_define (GumCModule * cm,
                            const gchar * name,
                            const gchar * value)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  tcc_define_symbol (self->state, name, value);
}

static void
gum_tcc_cmodule_add_symbol (GumCModule * cm,
                            const gchar * name,
                            gconstpointer value)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  tcc_add_symbol (self->state, name, value);
}

static gboolean
gum_tcc_cmodule_load (GumCModule * cm,
                      GumMemoryRange * range,
                      GString ** error_messages)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);
  TCCState * state = self->state;
  int res;
  gsize page_size, size;
  GumPageProtection protection;
  gpointer base;

  tcc_set_error_func (state, error_messages, gum_append_tcc_error);

  res = tcc_relocate_ex (state, NULL, 0);
  if (res == -1)
    return FALSE;

  self->size = res;

  page_size = gum_query_page_size ();
  size = GUM_ALIGN_SIZE (res, page_size);

  protection = gum_memory_can_remap_writable () ? GUM_PAGE_RX : GUM_PAGE_RW;

  base = gum_memory_allocate (NULL, size, page_size, protection);

  if (!gum_tcc_cmodule_relocate (self, base))
    goto relocation_failed;

  range->base_address = GUM_ADDRESS (base);
  range->size = size;

  return TRUE;

relocation_failed:
  {
    gum_memory_free (base, size);
    return FALSE;
  }
}

static gboolean
gum_tcc_cmodule_relocate (GumTccCModule * self,
                          gpointer base)
{
  if (gum_memory_can_remap_writable ())
  {
    GumTccApplyContext ctx;

    ctx.module = self;
    ctx.executable_base = base;
    ctx.success = FALSE;

    gum_memory_patch_code (base, self->size, gum_tcc_cmodule_relocate_views,
        &ctx);

    return ctx.success;
  }
  else
  {
    if (tcc_relocate_ex (self->state, base, 0) == -1)
      return FALSE;

    gum_memory_mark_code (base, self->size);

    return TRUE;
  }
}

static void
gum_tcc_cmodule_relocate_views (gpointer writable_base,
                                gpointer user_data)
{
  GumTccApplyContext * ctx = user_data;
  size_t diff_to_exec =
      (guint8 *) ctx->executable_base - (guint8 *) writable_base;

  ctx->success =
      tcc_relocate_ex (ctx->module->state, writable_base, diff_to_exec) != -1;
}

static void
gum_tcc_cmodule_link_post (GumCModule * cm)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  tcc_set_error_func (self->state, NULL, NULL);
}

static void
gum_tcc_cmodule_unload (GumCModule * cm,
                        const GumMemoryRange * range)
{
  gum_memory_free (GSIZE_TO_POINTER (range->base_address), range->size);
}

static void
gum_append_tcc_error (void * opaque,
                      const char * msg)
{
  GString ** messages = opaque;

  gum_append_error (messages, msg);
}

static void
gum_tcc_cmodule_enumerate_symbols (GumCModule * cm,
                                   GumFoundCSymbolFunc func,
                                   gpointer user_data)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);
  GumEnumerateSymbolsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  tcc_list_symbols (self->state, &ctx, gum_emit_symbol);
}

static void
gum_emit_symbol (void * ctx,
                 const char * name,
                 const void * val)
{
  GumEnumerateSymbolsContext * sc = ctx;
  GumCSymbolDetails d;

  d.name = gum_undecorate_name (name);
  d.address = (gpointer) val;

  sc->func (&d, sc->user_data);
}

static gpointer
gum_tcc_cmodule_find_symbol_by_name (GumCModule * cm,
                                     const gchar * name)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  return tcc_get_symbol (self->state, name);
}

static void
gum_tcc_cmodule_drop_metadata (GumCModule * cm)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  g_clear_pointer (&self->state, tcc_delete);
}

static const char *
gum_tcc_cmodule_load_header (void * opaque,
                             const char * path,
                             int * len)
{
  const gchar * name;
  guint i;

  name = path;
  if (g_str_has_prefix (name, "/frida/"))
    name += 7;

  for (i = 0; i != G_N_ELEMENTS (gum_cmodule_headers); i++)
  {
    const GumCHeaderDetails * h = &gum_cmodule_headers[i];
    if (strcmp (h->name, name) == 0)
    {
      *len = h->size;
      return h->data;
    }
  }

  return NULL;
}

static void *
gum_tcc_cmodule_resolve_symbol (void * opaque,
                                const char * name)
{
  return g_hash_table_lookup (gum_cmodule_get_symbols (),
      gum_undecorate_name (name));
}

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4

static long long gum_divdi3 (long long a, long long b);
static long long gum_moddi3 (long long a, long long b);
static long gum_fixdfdi (double value);

static void
gum_add_abi_symbols (TCCState * state)
{
  tcc_add_symbol (state, "__divdi3", GUM_FUNCPTR_TO_POINTER (gum_divdi3));
  tcc_add_symbol (state, "__moddi3", GUM_FUNCPTR_TO_POINTER (gum_moddi3));
  tcc_add_symbol (state, "__fixdfdi", GUM_FUNCPTR_TO_POINTER (gum_fixdfdi));
}

static long long
gum_divdi3 (long long a,
            long long b)
{
  return a / b;
}

static long long
gum_moddi3 (long long a,
            long long b)
{
  return a % b;
}

static long
gum_fixdfdi (double value)
{
  return value;
}

#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8 && \
    !defined (_MSC_VER) && !defined (__MINGW32__)

extern void * __va_arg (void * ap, int arg_type, int size, int align);

static void
gum_add_abi_symbols (TCCState * state)
{
  tcc_add_symbol (state, "__va_arg", __va_arg);
}

#elif defined (HAVE_ARM)

#define GUM_DECLARE_HELPER(name) \
    extern void __aeabi_ ## name (void);
#define GUM_DECLARE_HELPER_FALLBACK(name, ...) \
    static void gum_aeabi_ ## name (__VA_ARGS__);
#define GUM_REGISTER_HELPER(name) \
    tcc_add_symbol (state, G_STRINGIFY (__aeabi_ ## name), __aeabi_ ## name)
#define GUM_REGISTER_HELPER_FALLBACK(name) \
    GUM_REGISTER_HELPER_FALLBACK_ALIASED (name, name)
#define GUM_REGISTER_HELPER_FALLBACK_ALIASED(name, impl) \
    tcc_add_symbol (state, G_STRINGIFY (__aeabi_ ## name), gum_aeabi_ ## impl)

#ifdef HAVE_AEABI_MEMORY_BUILTINS
GUM_DECLARE_HELPER (memmove)
GUM_DECLARE_HELPER (memmove4)
GUM_DECLARE_HELPER (memmove8)
GUM_DECLARE_HELPER (memset)
#else
GUM_DECLARE_HELPER_FALLBACK (memmove, void *, const void *, size_t)
GUM_DECLARE_HELPER_FALLBACK (memset, void *, size_t, int)
#endif
#ifndef HAVE_DARWIN
GUM_DECLARE_HELPER (f2ulz)
GUM_DECLARE_HELPER (f2lz)
GUM_DECLARE_HELPER (d2ulz)
GUM_DECLARE_HELPER (d2lz)
GUM_DECLARE_HELPER (ul2f)
GUM_DECLARE_HELPER (l2f)
GUM_DECLARE_HELPER (ul2d)
GUM_DECLARE_HELPER (l2d)
GUM_DECLARE_HELPER (ldivmod)
GUM_DECLARE_HELPER (uldivmod)
GUM_DECLARE_HELPER (llsl)
GUM_DECLARE_HELPER (llsr)
GUM_DECLARE_HELPER (lasr)
GUM_DECLARE_HELPER (idiv)
GUM_DECLARE_HELPER (uidiv)
GUM_DECLARE_HELPER (idivmod)
GUM_DECLARE_HELPER (uidivmod)
#endif

static void
gum_add_abi_symbols (TCCState * state)
{
#ifdef HAVE_AEABI_MEMORY_BUILTINS
  GUM_REGISTER_HELPER (memmove);
  GUM_REGISTER_HELPER (memmove4);
  GUM_REGISTER_HELPER (memmove8);
  GUM_REGISTER_HELPER (memset);
#else
  GUM_REGISTER_HELPER_FALLBACK (memmove);
  GUM_REGISTER_HELPER_FALLBACK_ALIASED (memmove4, memmove);
  GUM_REGISTER_HELPER_FALLBACK_ALIASED (memmove8, memmove);
  GUM_REGISTER_HELPER_FALLBACK (memset);
#endif
#ifndef HAVE_DARWIN
  GUM_REGISTER_HELPER (f2ulz);
  GUM_REGISTER_HELPER (f2lz);
  GUM_REGISTER_HELPER (d2ulz);
  GUM_REGISTER_HELPER (d2lz);
  GUM_REGISTER_HELPER (ul2f);
  GUM_REGISTER_HELPER (l2f);
  GUM_REGISTER_HELPER (ul2d);
  GUM_REGISTER_HELPER (l2d);
  GUM_REGISTER_HELPER (ldivmod);
  GUM_REGISTER_HELPER (uldivmod);
  GUM_REGISTER_HELPER (llsl);
  GUM_REGISTER_HELPER (llsr);
  GUM_REGISTER_HELPER (lasr);
  GUM_REGISTER_HELPER (idiv);
  GUM_REGISTER_HELPER (uidiv);
  GUM_REGISTER_HELPER (idivmod);
  GUM_REGISTER_HELPER (uidivmod);
#endif
}

#ifndef HAVE_AEABI_MEMORY_BUILTINS

static void
gum_aeabi_memmove (void * dst,
                   const void * src,
                   size_t n)
{
  memmove (dst, src, n);
}

static void
gum_aeabi_memset (void * s,
                  size_t n,
                  int c)
{
  memset (s, c, n);
}

#endif

#else

static void
gum_add_abi_symbols (TCCState * state)
{
}

#endif

static const gchar *
gum_undecorate_name (const gchar * name)
{
#ifdef HAVE_DARWIN
  return name + 1;
#else
  return name;
#endif
}

#endif /* HAVE_TINYCC */

#ifndef G_OS_NONE

#if defined (HAVE_WINDOWS)
# define GUM_EXTERNAL_CMODULE_BINARY_NAME "module.dll"
#elif defined (HAVE_DARWIN)
# define GUM_EXTERNAL_CMODULE_BINARY_NAME "module.dylib"
#else
# define GUM_EXTERNAL_CMODULE_BINARY_NAME "module.so"
#endif

#define GUM_TYPE_EXTERNAL_CMODULE (gum_external_cmodule_get_type ())
G_DECLARE_FINAL_TYPE (GumExternalCModule, gum_external_cmodule, GUM,
    EXTERNAL_CMODULE, GumCModule)

typedef struct _GumEnumerateExportsContext GumEnumerateExportsContext;

struct _GumExternalCModule
{
  GumCModule parent;

  GBytes * binary;
  gchar * source;
  gchar * workdir;
  GPtrArray * defines;
  GHashTable * symbols;

  GumModuleResolver * resolver;
  GumMapper * mapper;
};

struct _GumEnumerateExportsContext
{
  GumFoundCSymbolFunc func;
  gpointer user_data;
};

static void gum_external_cmodule_add_define (GumCModule * cm,
    const gchar * name, const gchar * value);
static void gum_external_cmodule_add_symbol (GumCModule * cm,
    const gchar * name, gconstpointer value);
static gboolean gum_external_cmodule_load (GumCModule * cm,
    GumMemoryRange * range, GString ** error_messages);
static void gum_append_link_error (GString ** messages, const GError * error);
static void gum_external_cmodule_link_post (GumCModule * cm);
static void gum_external_cmodule_unload (GumCModule * cm,
    const GumMemoryRange * range);
static void gum_external_cmodule_enumerate_symbols (GumCModule * cm,
    GumFoundCSymbolFunc func, gpointer user_data);
static gboolean gum_emit_export (const GumExportDetails * details,
    gpointer user_data);
static gpointer gum_external_cmodule_find_symbol_by_name (GumCModule * cm,
    const gchar * name);
static void gum_external_cmodule_drop_metadata (GumCModule * cm);
static GBytes * gum_external_cmodule_compile (GumExternalCModule * self,
    GError ** error);
static gboolean gum_external_cmodule_build (GumExternalCModule * self,
    GError ** error);
#ifdef HAVE_WINDOWS
static void gum_append_export (gpointer key, gpointer value,
    gpointer user_data);
static gboolean gum_external_cmodule_build_with_msvc (GumExternalCModule * self,
    GError ** error);
static gboolean gum_external_cmodule_build_with_mingw (
    GumExternalCModule * self, GError ** error);
#endif
#ifndef HAVE_DARWIN
static void gum_add_gcc_machine_flag (GPtrArray * argv);
#endif
static void gum_external_cmodule_add_common_args (GumExternalCModule * self,
    GPtrArray * argv);
static gboolean gum_external_cmodule_run_tool (GumExternalCModule * self,
    GPtrArray * argv, GError ** error);
static GumModuleResolver * gum_external_cmodule_create_resolver (
    GumExternalCModule * self);
static GumAddress gum_external_cmodule_resolve_symbol (const gchar * symbol,
    gpointer user_data);

G_DEFINE_TYPE (GumExternalCModule, gum_external_cmodule, GUM_TYPE_CMODULE)

static void
gum_external_cmodule_class_init (GumExternalCModuleClass * klass)
{
  GumCModuleClass * cmodule_class = GUM_CMODULE_CLASS (klass);

  cmodule_class->add_define = gum_external_cmodule_add_define;
  cmodule_class->add_symbol = gum_external_cmodule_add_symbol;
  cmodule_class->load = gum_external_cmodule_load;
  cmodule_class->link_post = gum_external_cmodule_link_post;
  cmodule_class->unload = gum_external_cmodule_unload;
  cmodule_class->enumerate_symbols = gum_external_cmodule_enumerate_symbols;
  cmodule_class->find_symbol_by_name =
      gum_external_cmodule_find_symbol_by_name;
  cmodule_class->drop_metadata = gum_external_cmodule_drop_metadata;
}

static void
gum_external_cmodule_init (GumExternalCModule * self)
{
  self->defines = g_ptr_array_new_with_free_func (g_free);
  self->symbols = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
}

static GumCModule *
gum_external_cmodule_new (const gchar * source,
                          GBytes * binary,
                          const GumCModuleOptions * options,
                          GError ** error)
{
  GumCModule * result;
  GumExternalCModule * cmodule;

  result = g_object_new (GUM_TYPE_EXTERNAL_CMODULE, NULL);
  cmodule = GUM_EXTERNAL_CMODULE (result);

  if (binary != NULL)
    cmodule->binary = g_bytes_ref (binary);
  else
    cmodule->source = g_strdup (source);

  gum_cmodule_add_standard_defines (result);

  return result;
}

static void
gum_external_cmodule_add_define (GumCModule * cm,
                                 const gchar * name,
                                 const gchar * value)
{
  GumExternalCModule * self = GUM_EXTERNAL_CMODULE (cm);
  gchar * arg;

  arg = (value == NULL)
      ? g_strconcat ("-D", name, NULL)
      : g_strconcat ("-D", name, "=", value, NULL);

  g_ptr_array_add (self->defines, arg);
}

static void
gum_external_cmodule_add_symbol (GumCModule * cm,
                                 const gchar * name,
                                 gconstpointer value)
{
  GumExternalCModule * self = GUM_EXTERNAL_CMODULE (cm);

  g_hash_table_insert (self->symbols, g_strdup (name), (gpointer) value);
}

static gboolean
gum_external_cmodule_load (GumCModule * cm,
                           GumMemoryRange * range,
                           GString ** error_messages)
{
  GumExternalCModule * self = GUM_EXTERNAL_CMODULE (cm);
  GError * error = NULL;
  GumMapperConstructor ctor;
  GumCModulePrivate * priv = gum_cmodule_get_instance_private (cm);

  if (self->binary == NULL)
  {
    self->binary = gum_external_cmodule_compile (self, &error);
    if (error != NULL)
      goto propagate_error;
  }

  self->resolver = gum_external_cmodule_create_resolver (self);

  self->mapper = gum_mapper_new_take_blob (GUM_EXTERNAL_CMODULE_BINARY_NAME,
      g_steal_pointer (&self->binary), self->resolver, &error);
  if (error != NULL)
    goto propagate_error;

  if (!gum_mapper_map (self->mapper, 0, NULL, &error))
    goto propagate_link_error;

  *range = *gum_mapper_get_range (self->mapper);

  ctor = GSIZE_TO_POINTER (gum_mapper_constructor (self->mapper));
  ctor ();

  priv->destruct = GSIZE_TO_POINTER (gum_mapper_destructor (self->mapper));

  return TRUE;

propagate_error:
  {
    gum_append_error (error_messages, error->message);
    g_error_free (error);
    return FALSE;
  }
propagate_link_error:
  {
    gum_append_link_error (error_messages, error);
    g_error_free (error);
    g_clear_object (&self->mapper);
    return FALSE;
  }
}

static void
gum_append_link_error (GString ** messages,
                       const GError * error)
{
  const gchar * name_start, * name_end;
  gchar * name, * message;

  if (!g_error_matches (error, GUM_ERROR, GUM_ERROR_NOT_FOUND))
  {
    gum_append_error (messages, error->message);
    return;
  }

  name_start = g_utf8_find_next_char (strstr (error->message, "“"), NULL);
  name_end = strstr (name_start, "”");

  name = g_strndup (name_start, name_end - name_start);
  message = g_strdup_printf ("undefined reference to `%s'", name);

  gum_append_error (messages, message);

  g_free (message);
  g_free (name);
}

static void
gum_external_cmodule_link_post (GumCModule * cm)
{
}

static void
gum_external_cmodule_unload (GumCModule * cm,
                             const GumMemoryRange * range)
{
  GumExternalCModule * self = GUM_EXTERNAL_CMODULE (cm);

  gum_mapper_unmap (self->mapper);
  g_clear_object (&self->mapper);
}

static void
gum_external_cmodule_enumerate_symbols (GumCModule * cm,
                                        GumFoundCSymbolFunc func,
                                        gpointer user_data)
{
  GumExternalCModule * self = GUM_EXTERNAL_CMODULE (cm);
  GumEnumerateExportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_mapper_enumerate_exports (self->mapper, gum_emit_export, &ctx);
}

static gboolean
gum_emit_export (const GumExportDetails * details,
                 gpointer user_data)
{
  GumEnumerateExportsContext * ctx = user_data;
  GumCSymbolDetails d;

  d.name = details->name;
  d.address = GSIZE_TO_POINTER (details->address);

  ctx->func (&d, ctx->user_data);

  return TRUE;
}

static gpointer
gum_external_cmodule_find_symbol_by_name (GumCModule * cm,
                                          const gchar * name)
{
  GumExternalCModule * self = GUM_EXTERNAL_CMODULE (cm);

  return GSIZE_TO_POINTER (gum_mapper_resolve (self->mapper, name));
}

static void
gum_external_cmodule_drop_metadata (GumCModule * cm)
{
  GumExternalCModule * self = GUM_EXTERNAL_CMODULE (cm);

  g_clear_object (&self->resolver);

  g_clear_pointer (&self->symbols, g_hash_table_unref);
  g_clear_pointer (&self->defines, g_ptr_array_unref);

  if (self->workdir != NULL)
  {
    GFile * workdir_file = g_file_new_for_path (self->workdir);

    gum_rmtree (workdir_file);
    g_object_unref (workdir_file);

    g_free (self->workdir);
    self->workdir = NULL;
  }

  g_clear_pointer (&self->binary, g_bytes_unref);
  g_clear_pointer (&self->source, g_free);
}

static GBytes *
gum_external_cmodule_compile (GumExternalCModule * self,
                              GError ** error)
{
  GBytes * result = NULL;
  gchar * source_path = NULL;
  gchar * binary_path = NULL;
  gpointer data;
  gsize size;

  self->workdir = g_dir_make_tmp ("cmodule-XXXXXX", error);
  if (self->workdir == NULL)
    goto beach;

  source_path = g_build_filename (self->workdir, "module.c", NULL);
  if (!g_file_set_contents (source_path, self->source, -1, error))
    goto beach;

  if (!gum_populate_include_dir (self->workdir, error))
    goto beach;

  if (!gum_external_cmodule_build (self, error))
    goto beach;

  binary_path = g_build_filename (self->workdir,
      GUM_EXTERNAL_CMODULE_BINARY_NAME, NULL);
  if (!g_file_get_contents (binary_path, (gchar **) &data, &size, error))
    goto beach;

  result = g_bytes_new_take (data, size);

beach:
  {
    g_free (binary_path);
    g_free (source_path);

    return result;
  }
}

#if defined (HAVE_WINDOWS)

static gboolean
gum_external_cmodule_build (GumExternalCModule * self,
                            GError ** error)
{
  gboolean success = FALSE;
  GString * def;
  gchar * def_path;
  gchar * cl_path;

  def = g_string_new ("LIBRARY frida-cmodule-runtime.dll\nEXPORTS\n");
  g_hash_table_foreach (gum_cmodule_get_symbols (), gum_append_export, def);
  g_hash_table_foreach (self->symbols, gum_append_export, def);

  def_path = g_build_filename (self->workdir, "runtime.def", NULL);
  if (!g_file_set_contents (def_path, def->str, -1, error))
    goto beach;

  cl_path = g_find_program_in_path ("cl");
  success = (cl_path != NULL)
      ? gum_external_cmodule_build_with_msvc (self, error)
      : gum_external_cmodule_build_with_mingw (self, error);
  g_free (cl_path);

beach:
  {
    g_free (def_path);
    g_string_free (def, TRUE);

    return success;
  }
}

static void
gum_append_export (gpointer key,
                   gpointer value,
                   gpointer user_data)
{
  const gchar * name = key;
  GString * def = user_data;

  g_string_append_printf (def, "  %s\n", name);
}

static gboolean
gum_external_cmodule_build_with_msvc (GumExternalCModule * self,
                                      GError ** error)
{
  gboolean success = FALSE;
  const gchar * machine;
  GPtrArray * lib_argv;
  GPtrArray * cl_argv = NULL;
  guint i;

#if defined (HAVE_ARM64)
  machine = "ARM64";
#elif GLIB_SIZEOF_VOID_P == 8
  machine = "X64";
#else
  machine = "X86";
#endif

  lib_argv = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (lib_argv, g_strdup ("lib"));
  g_ptr_array_add (lib_argv, g_strdup ("-nologo"));
  g_ptr_array_add (lib_argv, g_strdup ("-def:runtime.def"));
  g_ptr_array_add (lib_argv, g_strdup ("-out:runtime.lib"));
  g_ptr_array_add (lib_argv, g_strconcat ("-machine:", machine, NULL));
  g_ptr_array_add (lib_argv, NULL);
  if (!gum_external_cmodule_run_tool (self, lib_argv, error))
    goto beach;

  cl_argv = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (cl_argv, g_strdup ("cl"));
  g_ptr_array_add (cl_argv, g_strdup ("-nologo"));
  g_ptr_array_add (cl_argv, g_strdup ("-LD"));
  g_ptr_array_add (cl_argv, g_strdup ("-O2"));
  g_ptr_array_add (cl_argv, g_strdup ("-I."));
  g_ptr_array_add (cl_argv, g_strdup ("-Icapstone"));
  for (i = 0; i != self->defines->len; i++)
    g_ptr_array_add (cl_argv, g_strdup (g_ptr_array_index (self->defines, i)));
  g_ptr_array_add (cl_argv, g_strdup ("module.c"));
  g_ptr_array_add (cl_argv, g_strdup ("-link"));
  g_ptr_array_add (cl_argv,
      g_strdup ("-out:" GUM_EXTERNAL_CMODULE_BINARY_NAME));
  g_ptr_array_add (cl_argv, g_strdup ("runtime.lib"));
  g_ptr_array_add (cl_argv, NULL);
  if (!gum_external_cmodule_run_tool (self, cl_argv, error))
    goto beach;

  success = TRUE;

beach:
  {
    g_clear_pointer (&cl_argv, g_ptr_array_unref);
    g_ptr_array_unref (lib_argv);

    return success;
  }
}

static gboolean
gum_external_cmodule_build_with_mingw (GumExternalCModule * self,
                                       GError ** error)
{
  gboolean success = FALSE;
  GPtrArray * dlltool_argv;
  gchar * entry_path = NULL;
  GPtrArray * gcc_argv = NULL;

  dlltool_argv = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (dlltool_argv, g_strdup ("dlltool"));
  g_ptr_array_add (dlltool_argv, g_strdup ("--input-def"));
  g_ptr_array_add (dlltool_argv, g_strdup ("runtime.def"));
  g_ptr_array_add (dlltool_argv, g_strdup ("--output-lib"));
  g_ptr_array_add (dlltool_argv, g_strdup ("runtime.a"));
  g_ptr_array_add (dlltool_argv, NULL);
  if (!gum_external_cmodule_run_tool (self, dlltool_argv, error))
    goto beach;

  entry_path = g_build_filename (self->workdir, "entry.c", NULL);
  if (!g_file_set_contents (entry_path,
      "int __stdcall\n"
      "DllMainCRTStartup (void * module, unsigned long reason, "
          "void * reserved)\n"
      "{\n"
      "  return 1;\n"
      "}\n",
      -1, error))
  {
    goto beach;
  }

  gcc_argv = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (gcc_argv, g_strdup ("gcc"));
  gum_add_gcc_machine_flag (gcc_argv);
  g_ptr_array_add (gcc_argv, g_strdup ("-shared"));
  g_ptr_array_add (gcc_argv, g_strdup ("-nostdlib"));
  gum_external_cmodule_add_common_args (self, gcc_argv);
  g_ptr_array_add (gcc_argv, g_strdup ("entry.c"));
  g_ptr_array_add (gcc_argv, g_strdup ("runtime.a"));
  g_ptr_array_add (gcc_argv, NULL);
  if (!gum_external_cmodule_run_tool (self, gcc_argv, error))
    goto beach;

  success = TRUE;

beach:
  {
    g_clear_pointer (&gcc_argv, g_ptr_array_unref);
    g_free (entry_path);
    g_ptr_array_unref (dlltool_argv);

    return success;
  }
}

#elif defined (HAVE_DARWIN)

static gboolean
gum_external_cmodule_build (GumExternalCModule * self,
                            GError ** error)
{
  gboolean success;
  const gchar * arch;
  GPtrArray * argv;

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  arch = "i386";
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  arch = "x86_64";
#elif defined (HAVE_ARM)
  arch = "armv7";
#elif defined (HAVE_ARM64) && defined (HAVE_PTRAUTH)
  arch = "arm64e";
#elif defined (HAVE_ARM64)
  arch = "arm64";
#else
# error Unsupported architecture.
#endif

  argv = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (argv, g_strdup ("clang"));
  g_ptr_array_add (argv, g_strdup ("-arch"));
  g_ptr_array_add (argv, g_strdup (arch));
  g_ptr_array_add (argv, g_strdup ("-dynamiclib"));
  gum_external_cmodule_add_common_args (self, argv);
  g_ptr_array_add (argv, g_strdup ("-Wl,-undefined,dynamic_lookup"));
  g_ptr_array_add (argv, NULL);

  success = gum_external_cmodule_run_tool (self, argv, error);

  g_ptr_array_unref (argv);

  return success;
}

#else

static gboolean
gum_external_cmodule_build (GumExternalCModule * self,
                            GError ** error)
{
  gboolean success;
  GPtrArray * argv;

  argv = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (argv, g_strdup ("gcc"));
  gum_add_gcc_machine_flag (argv);
  g_ptr_array_add (argv, g_strdup ("-shared"));
  g_ptr_array_add (argv, g_strdup ("-fPIC"));
  g_ptr_array_add (argv, g_strdup ("-nostdlib"));
  gum_external_cmodule_add_common_args (self, argv);
  g_ptr_array_add (argv, NULL);

  success = gum_external_cmodule_run_tool (self, argv, error);

  g_ptr_array_unref (argv);

  return success;
}

#endif

#ifndef HAVE_DARWIN

static void
gum_add_gcc_machine_flag (GPtrArray * argv)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  g_ptr_array_add (argv, g_strdup ("-m64"));
#elif defined (HAVE_I386)
  g_ptr_array_add (argv, g_strdup ("-m32"));
#endif
}

#endif

static void
gum_external_cmodule_add_common_args (GumExternalCModule * self,
                                      GPtrArray * argv)
{
  guint i;

  g_ptr_array_add (argv, g_strdup ("-Wall"));
  g_ptr_array_add (argv, g_strdup ("-Werror"));
  g_ptr_array_add (argv, g_strdup ("-O2"));
  g_ptr_array_add (argv, g_strdup ("-isystem"));
  g_ptr_array_add (argv, g_strdup ("."));
  g_ptr_array_add (argv, g_strdup ("-isystem"));
  g_ptr_array_add (argv, g_strdup ("capstone"));
  for (i = 0; i != self->defines->len; i++)
    g_ptr_array_add (argv, g_strdup (g_ptr_array_index (self->defines, i)));
  g_ptr_array_add (argv, g_strdup ("module.c"));
  g_ptr_array_add (argv, g_strdup ("-o"));
  g_ptr_array_add (argv, g_strdup (GUM_EXTERNAL_CMODULE_BINARY_NAME));
}

static gboolean
gum_external_cmodule_run_tool (GumExternalCModule * self,
                               GPtrArray * argv,
                               GError ** error)
{
  gboolean success = FALSE;
  gchar * output = NULL;
  gint exit_status;

  if (!gum_call_tool (self->workdir, (const gchar * const *) argv->pdata,
      &output, &exit_status, error))
  {
    goto beach;
  }

  if (exit_status != 0)
    goto tool_failed;

  success = TRUE;
  goto beach;

tool_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Compilation failed: %s", output);
    goto beach;
  }
beach:
  {
    g_free (output);

    return success;
  }
}

static GumModuleResolver *
gum_external_cmodule_create_resolver (GumExternalCModule * self)
{
#ifdef HAVE_DARWIN
  GumDarwinModuleResolver * resolver;

  resolver = gum_darwin_module_resolver_new (mach_task_self (), NULL);
  gum_darwin_module_resolver_set_dynamic_lookup_handler (resolver,
      gum_external_cmodule_resolve_symbol, self, NULL);
#else
  GumNativeModuleResolver * resolver;

  resolver = gum_native_module_resolver_new ();
  gum_native_module_resolver_set_dynamic_lookup_handler (resolver,
      gum_external_cmodule_resolve_symbol, self, NULL);
#endif

  return GUM_MODULE_RESOLVER (resolver);
}

static GumAddress
gum_external_cmodule_resolve_symbol (const gchar * symbol,
                                     gpointer user_data)
{
  GumExternalCModule * self = GUM_EXTERNAL_CMODULE (user_data);
  gpointer address;

  address = g_hash_table_lookup (self->symbols, symbol);
  if (address == NULL)
    address = g_hash_table_lookup (gum_cmodule_get_symbols (), symbol);

  return GUM_ADDRESS (address);
}

static gboolean
gum_populate_include_dir (const gchar * path,
                          GError ** error)
{
  guint i;

  for (i = 0; i != G_N_ELEMENTS (gum_cmodule_headers); i++)
  {
    const GumCHeaderDetails * h = &gum_cmodule_headers[i];
    gchar * filename, * dirname;
    gboolean written;

    if (h->kind != GUM_CHEADER_FRIDA)
      continue;

    filename = g_build_filename (path, h->name, NULL);
    dirname = g_path_get_dirname (filename);

    g_mkdir_with_parents (dirname, 0700);
    written = g_file_set_contents (filename, h->data, h->size, error);

    g_free (dirname);
    g_free (filename);

    if (!written)
      return FALSE;
  }

  return TRUE;
}

static void
gum_rmtree (GFile * file)
{
  GFileEnumerator * enumerator;

  enumerator = g_file_enumerate_children (file,
      G_FILE_ATTRIBUTE_STANDARD_NAME "," G_FILE_ATTRIBUTE_STANDARD_TYPE,
      G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, NULL);
  if (enumerator != NULL)
  {
    GFileInfo * info;
    GFile * child;

    while (g_file_enumerator_iterate (enumerator, &info, &child, NULL, NULL) &&
        child != NULL)
    {
      if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
        gum_rmtree (child);
      else
        g_file_delete (child, NULL, NULL);
    }

    g_object_unref (enumerator);
  }

  g_file_delete (file, NULL, NULL);
}

#ifdef HAVE_WINDOWS

static gboolean
gum_call_tool (const gchar * cwd,
               const gchar * const * argv,
               gchar ** output,
               gint * exit_status,
               GError ** error)
{
  gboolean success = FALSE;
  GString * command_line;
  guint i;
  SECURITY_ATTRIBUTES pipe_attributes =
      { sizeof (pipe_attributes), NULL, TRUE };
  HANDLE read_end = NULL, write_end = NULL;
  STARTUPINFOW si = { 0, };
  PROCESS_INFORMATION pi = { 0, };
  WCHAR * command_line_utf16 = NULL, * cwd_utf16 = NULL;
  GString * collected;
  gchar buffer[4096];
  DWORD n, code;

  command_line = g_string_new (NULL);
  for (i = 0; argv[i] != NULL; i++)
  {
    if (i != 0)
      g_string_append_c (command_line, ' ');
    gum_append_quoted_argument (command_line, argv[i]);
  }

  if (!CreatePipe (&read_end, &write_end, &pipe_attributes, 0))
    goto spawn_failed;
  SetHandleInformation (read_end, HANDLE_FLAG_INHERIT, 0);

  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = write_end;
  si.hStdError = write_end;

  command_line_utf16 = g_utf8_to_utf16 (command_line->str, -1, NULL, NULL,
      NULL);
  cwd_utf16 = g_utf8_to_utf16 (cwd, -1, NULL, NULL, NULL);

  if (!CreateProcessW (NULL, command_line_utf16, NULL, NULL, TRUE,
      CREATE_NO_WINDOW, NULL, cwd_utf16, &si, &pi))
  {
    goto spawn_failed;
  }

  CloseHandle (write_end);
  write_end = NULL;

  collected = g_string_new (NULL);
  while (ReadFile (read_end, buffer, sizeof (buffer), &n, NULL) && n != 0)
    g_string_append_len (collected, buffer, n);
  *output = g_string_free (collected, FALSE);

  WaitForSingleObject (pi.hProcess, INFINITE);
  GetExitCodeProcess (pi.hProcess, &code);
  *exit_status = code;

  CloseHandle (pi.hThread);
  CloseHandle (pi.hProcess);

  success = TRUE;
  goto beach;

spawn_failed:
  {
    gchar * message = g_win32_error_message (GetLastError ());

    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
        "Unable to execute “%s”: %s", argv[0], message);

    g_free (message);

    goto beach;
  }
beach:
  {
    g_free (cwd_utf16);
    g_free (command_line_utf16);
    if (write_end != NULL)
      CloseHandle (write_end);
    if (read_end != NULL)
      CloseHandle (read_end);
    g_string_free (command_line, TRUE);

    return success;
  }
}

static void
gum_append_quoted_argument (GString * command_line,
                            const gchar * arg)
{
  const gchar * p;
  guint backslashes;

  if (arg[0] != '\0' && strpbrk (arg, " \t\"") == NULL)
  {
    g_string_append (command_line, arg);
    return;
  }

  g_string_append_c (command_line, '"');

  backslashes = 0;
  for (p = arg; *p != '\0'; p++)
  {
    if (*p == '\\')
    {
      backslashes++;
      continue;
    }

    if (*p == '"')
      backslashes = (backslashes * 2) + 1;

    for (; backslashes != 0; backslashes--)
      g_string_append_c (command_line, '\\');

    g_string_append_c (command_line, *p);
  }

  for (backslashes *= 2; backslashes != 0; backslashes--)
    g_string_append_c (command_line, '\\');

  g_string_append_c (command_line, '"');
}

#else

static gboolean
gum_call_tool (const gchar * cwd,
               const gchar * const * argv,
               gchar ** output,
               gint * exit_status,
               GError ** error)
{
  GSubprocessLauncher * launcher;
  GSubprocess * proc;

  launcher = g_subprocess_launcher_new (
      G_SUBPROCESS_FLAGS_STDOUT_PIPE |
      G_SUBPROCESS_FLAGS_STDERR_MERGE);
  g_subprocess_launcher_set_cwd (launcher, cwd);
  proc = g_subprocess_launcher_spawnv (launcher, argv, error);
  g_object_unref (launcher);
  if (proc == NULL)
    goto propagate_error;

  if (!g_subprocess_communicate_utf8 (proc, NULL, NULL, output, NULL, error))
    goto propagate_error;

  *exit_status = g_subprocess_get_exit_status (proc);

  g_object_unref (proc);

  return TRUE;

propagate_error:
  {
    g_clear_object (&proc);

    return FALSE;
  }
}

#endif

#endif /* !G_OS_NONE */

static void
gum_append_error (GString ** messages,
                  const char * msg)
{
  if (*messages == NULL)
  {
    *messages = g_string_new (msg);
  }
  else
  {
    g_string_append_c (*messages, '\n');
    g_string_append (*messages, msg);
  }
}
