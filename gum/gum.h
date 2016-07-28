/*
 * Copyright (C) 2008-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_H__
#define __GUM_H__

#include <gum/gumdefs.h>

#include <gum/gumapiresolver.h>
#include <gum/gumbacktracer.h>
#include <gum/gumcodeallocator.h>
#include <gum/gumcodesegment.h>
#include <gum/gumexceptor.h>
#include <gum/gumevent.h>
#include <gum/gumeventsink.h>
#include <gum/gumfunction.h>
#include <gum/guminterceptor.h>
#include <gum/guminvocationcontext.h>
#include <gum/guminvocationlistener.h>
#include <gum/gumkernel.h>
#include <gum/gummemory.h>
#include <gum/gummemoryaccessmonitor.h>
#include <gum/gummemorymap.h>
#include <gum/gummoduleapiresolver.h>
#include <gum/gummodulemap.h>
#include <gum/gumprocess.h>
#include <gum/gumreturnaddress.h>
#include <gum/gumspinlock.h>
#include <gum/gumstalker.h>
#include <gum/gumsymbolutil.h>
#include <gum/gumsysinternals.h>
#include <gum/gumtls.h>

G_BEGIN_DECLS

GUM_API void gum_init (void);
GUM_API void gum_deinit (void);

G_END_DECLS

#endif
