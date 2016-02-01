/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_SOCKET_H__
#define __GUM_DUK_SOCKET_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukSocket GumDukSocket;

struct _GumDukSocket
{
  GumDukCore * core;
};

G_GNUC_INTERNAL void _gum_duk_socket_init (GumDukSocket * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_socket_dispose (GumDukSocket * self);
G_GNUC_INTERNAL void _gum_duk_socket_finalize (GumDukSocket * self);

G_END_DECLS

#endif
