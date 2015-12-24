/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSC_SCRIPT_PRIV_H__
#define __GUM_JSC_SCRIPT_PRIV_H__

#include "gumjsccore.h"
#include "gumjscfile.h"
#include "gumjscinstruction.h"
#include "gumjscinterceptor.h"
#include "gumjsckernel.h"
#include "gumjscmemory.h"
#include "gumjscmodule.h"
#include "gumjscpolyfill.h"
#include "gumjscprocess.h"
#include "gumjscsocket.h"
#include "gumjscstalker.h"
#include "gumjscsymbol.h"
#include "gumjscthread.h"

#include <glib.h>
#include <JavaScriptCore/JavaScriptCore.h>

G_BEGIN_DECLS

struct _GumJscScriptPrivate
{
  gchar * name;
  gchar * source;
  GMainContext * main_context;
  GumJscScriptBackend * backend;

  JSGlobalContextRef ctx;
  GumJscCore core;
  GumJscPolyfill polyfill;
  GumJscKernel kernel;
  GumJscMemory memory;
  GumJscProcess process;
  GumJscThread thread;
  GumJscModule module;
  GumJscFile file;
  GumJscSocket socket;
  GumJscInterceptor interceptor;
  GumJscStalker stalker;
  GumJscSymbol symbol;
  GumJscInstruction instruction;
  gboolean loaded;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;
};

G_GNUC_INTERNAL void _gumjs_panic (JSContextRef ctx, JSValueRef exception);

G_END_DECLS

#endif
