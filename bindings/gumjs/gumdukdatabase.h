/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_DATABASE_H__
#define __GUM_DUK_DATABASE_H__

#include "gumdukcore.h"
#include "gummemoryvfs.h"

G_BEGIN_DECLS

typedef struct _GumDukDatabase GumDukDatabase;

struct _GumDukDatabase
{
  GumDukCore * core;

  GumDukHeapPtr database;
  GumDukHeapPtr statement;
  GumMemoryVfs * memory_vfs;
};

G_GNUC_INTERNAL void _gum_duk_database_init (GumDukDatabase * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_database_dispose (GumDukDatabase * self);
G_GNUC_INTERNAL void _gum_duk_database_finalize (GumDukDatabase * self);

G_END_DECLS

#endif
