/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_PROCESS_H__
#define __GUM_DUK_PROCESS_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukProcess GumDukProcess;
typedef struct _GumDukExceptionHandler GumDukExceptionHandler;

struct _GumDukProcess
{
  GumDukCore * core;

  GumDukExceptionHandler * exception_handler;
};

G_GNUC_INTERNAL void _gum_duk_process_init (GumDukProcess * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_process_flush (GumDukProcess * self);
G_GNUC_INTERNAL void _gum_duk_process_dispose (GumDukProcess * self);
G_GNUC_INTERNAL void _gum_duk_process_finalize (GumDukProcess * self);

G_END_DECLS

#endif
