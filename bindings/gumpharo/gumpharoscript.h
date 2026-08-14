#ifndef __GUM_PHARO_SCRIPT_H__
#define __GUM_PHARO_SCRIPT_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

#define GUM_TYPE_PHARO_SCRIPT (gum_pharo_script_get_type ())
G_DECLARE_FINAL_TYPE (GumPharoScript, gum_pharo_script, GUM, PHARO_SCRIPT,
    GObject)

typedef void (* GumPharoScriptMessageHandler) (GumPharoScript * script,
    const gchar * message, GBytes * data, gpointer user_data);

GUM_API GumPharoScript * gum_pharo_script_new (const gchar * name,
    const gchar * source);
GUM_API void gum_pharo_script_load (GumPharoScript * self);
GUM_API void gum_pharo_script_unload (GumPharoScript * self);
GUM_API void gum_pharo_script_post (GumPharoScript * self,
    const gchar * message, GBytes * data);
GUM_API void gum_pharo_script_set_message_handler (GumPharoScript * self,
    GumPharoScriptMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);

G_END_DECLS

#endif
