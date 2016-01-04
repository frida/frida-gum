/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUKRIPT_POLYFILL_H__
#define __GUM_DUKRIPT_POLYFILL_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukPolyfill GumDukPolyfill;

struct _GumDukPolyfill
{
  GumDukCore * core;
};

G_GNUC_INTERNAL void _gum_duk_polyfill_init (GumDukPolyfill * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_polyfill_dispose (GumDukPolyfill * self);
G_GNUC_INTERNAL void _gum_duk_polyfill_finalize (GumDukPolyfill * self);

G_END_DECLS

#endif
