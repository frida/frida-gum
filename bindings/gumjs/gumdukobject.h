/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_UTILS_H__
#define __GUM_DUK_UTILS_H__

#include "duktape.h"

#include <glib.h>

typedef void * GumDukHeapPtr;
typedef struct _GumDukPropertyEntry GumDukPropertyEntry;

struct _GumDukPropertyEntry
{
  gchar * name;
  gpointer getter;
  gpointer setter;
};

G_GNUC_INTERNAL void _gumjs_duk_create_subclass (duk_context * ctx,
    const gchar * parent, const gchar * name, gpointer constructor,
    gint constructor_nargs, gpointer finalize);

G_GNUC_INTERNAL void _gumjs_duk_add_properties_to_class_by_heapptr (
    duk_context * ctx, GumDukHeapPtr klass,
    const GumDukPropertyEntry * entries);
G_GNUC_INTERNAL void _gumjs_duk_add_properties_to_class (duk_context * ctx,
    const gchar * class_name, const GumDukPropertyEntry * entries);

G_GNUC_INTERNAL gboolean _gumjs_is_arg0_equal_to_prototype (duk_context * ctx,
    const gchar * class_name);

G_GNUC_INTERNAL GumDukHeapPtr _gumjs_duk_get_this (duk_context * ctx);
G_GNUC_INTERNAL void _gumjs_duk_protect (duk_context * ctx,
    GumDukHeapPtr object);
G_GNUC_INTERNAL void _gumjs_duk_unprotect (duk_context * ctx,
    GumDukHeapPtr object);
G_GNUC_INTERNAL GumDukHeapPtr _gumjs_duk_get_heapptr (duk_context * ctx,
    gint idx);
G_GNUC_INTERNAL GumDukHeapPtr _gumjs_duk_require_heapptr (duk_context * ctx,
    gint idx);
G_GNUC_INTERNAL void _gumjs_duk_release_heapptr (duk_context * ctx,
    GumDukHeapPtr heapptr);
G_GNUC_INTERNAL GumDukHeapPtr _gumjs_duk_create_proxy_accessors (
    duk_context * ctx, gpointer getter, gpointer setter);

#endif
