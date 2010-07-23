/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_INVOCATION_CONTEXT_H__
#define __GUM_INVOCATION_CONTEXT_H__

#include <glib.h>
#include <gum/gumdefs.h>

typedef struct _GumInvocationBackend GumInvocationBackend;
typedef struct _GumInvocationContext GumInvocationContext;

struct _GumInvocationBackend
{
  gpointer (* get_nth_argument) (GumInvocationContext * context, guint n);
  void (* replace_nth_argument) (GumInvocationContext * context, guint n,
      gpointer value);
  gpointer (* get_return_value) (GumInvocationContext * context);

  gpointer user_data;
};

struct _GumInvocationContext
{
  GumInvocationContext * parent;

  gpointer instance_data;
  gpointer thread_data;

  GumCpuContext * cpu_context;

  /*< private */
  GumInvocationBackend * backend;
};

G_BEGIN_DECLS

GUM_API gpointer gum_invocation_context_get_nth_argument (
    GumInvocationContext * context, guint n);
GUM_API void gum_invocation_context_replace_nth_argument (
    GumInvocationContext * context, guint n, gpointer value);
GUM_API gpointer gum_invocation_context_get_return_value (
    GumInvocationContext * context);

G_END_DECLS

#endif
