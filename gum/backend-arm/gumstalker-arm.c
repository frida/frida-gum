/*
 * Copyright (C) 2012 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2012 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumstalker.h"

struct _GumStalkerPrivate
{
  gboolean dummy;
};

#define GUM_STALKER_GET_PRIVATE(o) ((o)->priv)

static void gum_stalker_finalize (GObject * object);

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT);

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumStalkerPrivate));

  object_class->finalize = gum_stalker_finalize;
}

static void
gum_stalker_init (GumStalker * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_STALKER, GumStalkerPrivate);
}

static void
gum_stalker_finalize (GObject * object)
{
  GumStalker * self = GUM_STALKER (object);

  (void) self;

  G_OBJECT_CLASS (gum_stalker_parent_class)->finalize (object);
}

GumStalker *
gum_stalker_new (void)
{
  return GUM_STALKER (g_object_new (GUM_TYPE_STALKER, NULL));
}

void
gum_stalker_exclude (GumStalker * self,
                     const GumMemoryRange * range)
{
}

gint
gum_stalker_get_trust_threshold (GumStalker * self)
{
  return -1;
}

void
gum_stalker_set_trust_threshold (GumStalker * self,
                                 gint trust_threshold)
{
}

void
gum_stalker_stop (GumStalker * self)
{
}

gboolean
gum_stalker_garbage_collect (GumStalker * self)
{
  return FALSE;
}

void
gum_stalker_follow_me (GumStalker * self,
                       GumEventSink * sink)
{
}

void
gum_stalker_unfollow_me (GumStalker * self)
{
}

gboolean
gum_stalker_is_following_me (GumStalker * self)
{
  return FALSE;
}

void
gum_stalker_follow (GumStalker * self,
                    GumThreadId thread_id,
                    GumEventSink * sink)
{
}

void
gum_stalker_unfollow (GumStalker * self,
                      GumThreadId thread_id)
{
}

GumProbeId
gum_stalker_add_call_probe (GumStalker * self,
                            gpointer target_address,
                            GumCallProbeCallback callback,
                            gpointer data,
                            GDestroyNotify notify)
{
  return 0;
}

void
gum_stalker_remove_call_probe (GumStalker * self,
                               GumProbeId id)
{
}

