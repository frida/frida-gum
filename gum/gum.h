/*
 * Copyright (C) 2008-2011 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_H__
#define __GUM_H__

#include <gum/gumdefs.h>

#include <gum/gumbacktracer.h>
#include <gum/gumclosure.h>
#include <gum/gumevent.h>
#include <gum/gumeventsink.h>
#include <gum/guminterceptor.h>
#include <gum/guminvocationlistener.h>
#include <gum/gumlist.h>
#include <gum/gummemory.h>
#include <gum/gummemoryaccessmonitor.h>
#include <gum/gumprocess.h>
#include <gum/gumreturnaddress.h>
#include <gum/gumscript.h>
#include <gum/gumstalker.h>
#include <gum/gumsymbolutil.h>
#include <gum/gumtracer.h>

G_BEGIN_DECLS

typedef guint GumFeatureFlags;

enum _GumFeatureFlags
{
  GUM_FEATURE_SYMBOL_LOOKUP = (1 << 0),

  GUM_FEATURE_NONE          = 0,
  GUM_FEATURE_ALL           = (GUM_FEATURE_SYMBOL_LOOKUP),
  GUM_FEATURE_DEFAULT       = GUM_FEATURE_ALL
};

GUM_API void gum_init (void);
GUM_API void gum_init_with_features (GumFeatureFlags features);
GUM_API void gum_deinit (void);

G_END_DECLS

#endif
