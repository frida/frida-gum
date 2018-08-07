/*
 * Copyright (C) 2015-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_SCRIPT_H__
#define __GUM_DUK_SCRIPT_H__

#include "gumscript.h"

G_BEGIN_DECLS

#define GUM_DUK_TYPE_SCRIPT (gum_duk_script_get_type ())
G_DECLARE_FINAL_TYPE (GumDukScript, gum_duk_script, GUM_DUK, SCRIPT, GObject)

G_GNUC_INTERNAL gboolean gum_duk_script_create_context (GumDukScript * self,
    GError ** error);

G_GNUC_INTERNAL void gum_duk_script_attach_debugger (GumDukScript * self);
G_GNUC_INTERNAL void gum_duk_script_detach_debugger (GumDukScript * self);
G_GNUC_INTERNAL void gum_duk_script_post_to_debugger (GumDukScript * self,
    GBytes * bytes);

G_END_DECLS

#endif
