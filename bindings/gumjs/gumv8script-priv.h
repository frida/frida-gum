/*
 * Copyright (C) 2015-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_SCRIPT_PRIV_H__
#define __GUM_V8_SCRIPT_PRIV_H__

#include "gumv8apiresolver.h"
#include "gumv8cmodule.h"
#include "gumv8coderelocator.h"
#include "gumv8codewriter.h"
#include "gumv8core.h"
#include "gumv8database.h"
#include "gumv8file.h"
#include "gumv8instruction.h"
#include "gumv8interceptor.h"
#include "gumv8kernel.h"
#include "gumv8memory.h"
#include "gumv8module.h"
#include "gumv8platform.h"
#include "gumv8process.h"
#include "gumv8scope.h"
#include "gumv8script.h"
#include "gumv8scriptbackend.h"
#include "gumv8socket.h"
#include "gumv8stalker.h"
#include "gumv8stream.h"
#include "gumv8symbol.h"
#include "gumv8thread.h"

typedef guint GumScriptState;

struct _GumV8Script
{
  GObject parent;

  gchar * name;
  gchar * source;
  GMainContext * main_context;
  GumV8ScriptBackend * backend;

  GumScriptState state;
  GSList * on_unload;
  v8::Isolate * isolate;
  GumV8Core core;
  GumV8Kernel kernel;
  GumV8Memory memory;
  GumV8Module module;
  GumV8Process process;
  GumV8Thread thread;
  GumV8File file;
  GumV8Stream stream;
  GumV8Socket socket;
  GumV8Database database;
  GumV8Interceptor interceptor;
  GumV8ApiResolver api_resolver;
  GumV8Symbol symbol;
  GumV8CModule cmodule;
  GumV8Instruction instruction;
  GumV8CodeWriter code_writer;
  GumV8CodeRelocator code_relocator;
  GumV8Stalker stalker;
  GumPersistent<v8::Context>::type * context;
  GumPersistent<v8::Script>::type * code;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;
};

#endif
