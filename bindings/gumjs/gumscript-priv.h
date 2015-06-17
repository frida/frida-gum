/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_PRIV_H__
#define __GUM_SCRIPT_PRIV_H__

#include "gumscript.h"
#include "gumscriptcore.h"
#include "gumscriptfile.h"
#include "gumscriptinstruction.h"
#include "gumscriptinterceptor.h"
#include "gumscriptmemory.h"
#include "gumscriptmodule.h"
#include "gumscriptplatform.h"
#include "gumscriptprocess.h"
#include "gumscriptscope.h"
#include "gumscriptsocket.h"
#include "gumscriptstalker.h"
#include "gumscriptsymbol.h"
#include "gumscripttask.h"
#include "gumscriptthread.h"

G_BEGIN_DECLS

struct _GumScriptPrivate
{
  gchar * name;
  gchar * source;
  GMainContext * main_context;

  v8::Isolate * isolate;
  GumScriptCore core;
  GumScriptMemory memory;
  GumScriptProcess process;
  GumScriptThread thread;
  GumScriptModule module;
  GumScriptFile file;
  GumScriptSocket socket;
  GumScriptInterceptor interceptor;
  GumScriptStalker stalker;
  GumScriptSymbol symbol;
  GumScriptInstruction instruction;
  GumPersistent<v8::Context>::type * context;
  GumPersistent<v8::Script>::type * code;
  gboolean loaded;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;
};

G_END_DECLS

#endif
