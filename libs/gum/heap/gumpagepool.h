/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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
typedef struct _GumBlockDetails GumBlockDetails;

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

struct _GumBlockDetails
{
  gpointer address;
  gsize size;
  gpointer guard;
  gsize guard_size;
  gboolean allocated;
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
gboolean gum_page_pool_query_block_details (GumPagePool * self,
    gconstpointer mem, GumBlockDetails * details);

G_END_DECLS

#endif
