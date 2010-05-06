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

#ifndef __GUM_H__
#define __GUM_H__

#include <gum/gumdefs.h>

#include <gum/gumallocationblock.h>
#include <gum/gumallocationgroup.h>
#include <gum/gumallocationtracker.h>
#include <gum/gumallocatorprobe.h>
#include <gum/gumbacktracer.h>
#include <gum/gumboundschecker.h>
#include <gum/gumbusycyclesampler.h>
#include <gum/gumcallcountsampler.h>
#include <gum/gumcobject.h>
#include <gum/gumcobjecttracker.h>
#include <gum/gumcyclesampler.h>
#include <gum/gumevent.h>
#include <gum/gumeventsink.h>
#include <gum/guminstancetracker.h>
#include <gum/guminterceptor.h>
#include <gum/guminvocationlistener.h>
#include <gum/gumlist.h>
#include <gum/gummalloccountsampler.h>
#include <gum/gumprofiler.h>
#include <gum/gumprofilereport.h>
#include <gum/gumreturnaddress.h>
#include <gum/gumsampler.h>
#include <gum/gumstalker.h>
#include <gum/gumsymbolutil.h>
#include <gum/gumtracer.h>
#include <gum/gumwallclocksampler.h>

#ifdef G_OS_WIN32
#include <gum/gumwindowsbacktracer.h>
#else
#include <gum/gumgnubacktracer.h>
#endif

G_BEGIN_DECLS

GUM_API void gum_init ();

G_END_DECLS

#endif
