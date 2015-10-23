/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_STALKER_H__
#define __GUM_JSCRIPT_STALKER_H__

#include "gumjscriptcore.h"

G_BEGIN_DECLS

typedef struct _GumScriptStalker GumScriptStalker;

struct _GumScriptStalker
{
  GumScriptCore * core;
  GumStalker * stalker;
};

G_GNUC_INTERNAL void _gum_script_stalker_init (GumScriptStalker * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_stalker_flush (GumScriptStalker * self);
G_GNUC_INTERNAL void _gum_script_stalker_dispose (GumScriptStalker * self);
G_GNUC_INTERNAL void _gum_script_stalker_finalize (GumScriptStalker * self);

G_GNUC_INTERNAL GumStalker * _gum_script_stalker_get (GumScriptStalker * self);

G_END_DECLS

#endif
