/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_PAGE_POOL_H__
#define __GUM_PAGE_POOL_H__

#include <glib-object.h>
#include <gum/gumdefs.h>

#define GUM_TYPE_PAGE_POOL (gum_page_pool_get_type ())
#define GUM_PAGE_POOL(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_PAGE_POOL, GumPagePool))
#define GUM_PAGE_POOL_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_PAGE_POOL, GumPagePoolClass))
#define GUM_IS_PAGE_POOL(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_PAGE_POOL))
#define GUM_IS_PAGE_POOL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_PAGE_POOL))
#define GUM_PAGE_POOL_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_PAGE_POOL, GumPagePoolClass))

typedef struct _GumPagePool GumPagePool;
typedef struct _GumPagePoolClass GumPagePoolClass;

typedef enum _GumProtectMode GumProtectMode;

typedef struct _GumPagePoolPrivate GumPagePoolPrivate;

struct _GumPagePool
{
  GObject parent;

  GumPagePoolPrivate * priv;
};

struct _GumPagePoolClass
{
  GObjectClass parent_class;
};

enum _GumProtectMode
{
  GUM_PROTECT_MODE_ABOVE = 1
};

G_BEGIN_DECLS

GType gum_page_pool_get_type (void) G_GNUC_CONST;

GumPagePool * gum_page_pool_new (GumProtectMode protect_mode, guint n_pages);

gpointer gum_page_pool_try_alloc (GumPagePool * self, guint size);
gboolean gum_page_pool_try_free (GumPagePool * self, gpointer mem);

guint gum_page_pool_peek_available (GumPagePool * self);
guint gum_page_pool_peek_used (GumPagePool * self);
void gum_page_pool_get_bounds (GumPagePool * self, guint8 ** lower,
    guint8 ** upper);
guint gum_page_pool_query_block_size (GumPagePool * self, gpointer mem);

G_END_DECLS

#endif
