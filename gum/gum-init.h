/*
 * Copyright (C) 2014-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_INIT_H__
#define __GUM_INIT_H__

#include <gum/gumdefs.h>

typedef void (* GumDestructorFunc) (void);

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_register_early_destructor (
    GumDestructorFunc destructor);
G_GNUC_INTERNAL void _gum_register_destructor (GumDestructorFunc destructor);

G_GNUC_INTERNAL gpointer gum_cs_malloc (gsize size);
G_GNUC_INTERNAL gpointer gum_cs_calloc (gsize count, gsize size);
G_GNUC_INTERNAL gpointer gum_cs_realloc (gpointer mem, gsize size);
G_GNUC_INTERNAL void gum_cs_free (gpointer mem);

G_END_DECLS

#endif
