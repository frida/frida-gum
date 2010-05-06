/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_EVENT_H__
#define __GUM_EVENT_H__

#include <glib-object.h>
#include <gum/gumdefs.h>

G_BEGIN_DECLS

typedef enum _GumEventType GumEventType;

typedef union _GumEvent GumEvent;

typedef struct _GumAnyEvent   GumAnyEvent;
typedef struct _GumCallEvent  GumCallEvent;
typedef struct _GumRetEvent   GumRetEvent;
typedef struct _GumExecEvent  GumExecEvent;

enum _GumEventType
{
  GUM_NOTHING     = 0,
  GUM_CALL        = 1 << 0,
  GUM_RET         = 1 << 1,
  GUM_EXEC        = 1 << 2,
};

struct _GumAnyEvent
{
  GumEventType type;
};

struct _GumCallEvent
{
  GumEventType type;

  gpointer location;
  gpointer target;
};

struct _GumRetEvent
{
  GumEventType type;

  gpointer location;
  gpointer target;
};

struct _GumExecEvent
{
  GumEventType type;

  gpointer location;
};

union _GumEvent
{
  GumEventType type;

  GumAnyEvent any;
  GumCallEvent call;
  GumRetEvent ret;
  GumExecEvent exec;
};

G_END_DECLS

#endif
