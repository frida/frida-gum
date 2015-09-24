/*
 * Copyright (C) 2008-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_H__
#define __GUM_H__

#include <gum/gumdefs.h>

#include <gum/gumbacktracer.h>
#include <gum/gumevent.h>
#include <gum/gumeventsink.h>
#include <gum/guminterceptor.h>
#include <gum/guminvocationlistener.h>
#include <gum/gumlist.h>
#include <gum/gummemory.h>
#include <gum/gummemoryaccessmonitor.h>
#include <gum/gummemorymap.h>
#include <gum/gummodulemap.h>
#include <gum/gumprocess.h>
#include <gum/gumreturnaddress.h>
#include <gum/gumstalker.h>
#include <gum/gumsymbolutil.h>

G_BEGIN_DECLS

GUM_API void gum_init (void);
GUM_API void gum_deinit (void);

G_END_DECLS

#endif
