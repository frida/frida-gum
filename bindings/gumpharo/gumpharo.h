#ifndef __GUM_PHARO_H__
#define __GUM_PHARO_H__

#include <gum/gumdefs.h>
#include <pharovm/pharo.h>
#include <pharovm/common/virtualMachine.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL sqInt gum_pharo_set_interpreter (
    struct VirtualMachine * interpreter);

G_GNUC_INTERNAL gpointer gum_pharo_pointer_at (sqInt index);
G_GNUC_INTERNAL guint64 gum_pharo_integer_at (sqInt index);
G_GNUC_INTERNAL gboolean gum_pharo_boolean_at (sqInt index);

G_GNUC_INTERNAL sqInt gum_pharo_return_pointer (gpointer value);
G_GNUC_INTERNAL sqInt gum_pharo_return_integer (guint64 value);
G_GNUC_INTERNAL sqInt gum_pharo_return_boolean (gboolean value);
G_GNUC_INTERNAL sqInt gum_pharo_return_self (void);

typedef void (* GumPharoMessageHandler) (const gchar * payload, GBytes * data,
    gpointer user_data);

GUM_API void gum_pharo_set_message_handler (GumPharoMessageHandler handler,
    gpointer user_data);
GUM_API void gum_pharo_post (const gchar * payload, GBytes * data);
GUM_API void gum_pharo_runtime_ensure_started (void);
GUM_API void gum_pharo_runtime_evaluate (const gchar * source);

G_GNUC_INTERNAL gconstpointer gum_pharo_bytes_at (sqInt index, gsize * size);
G_GNUC_INTERNAL gchar * gum_pharo_string_at (sqInt index);
G_GNUC_INTERNAL void gum_pharo_signal_semaphore (sqInt index);

G_GNUC_INTERNAL sqInt gum_pharo_return_string (const gchar * value,
    gsize size);
G_GNUC_INTERNAL sqInt gum_pharo_return_byte_array (gconstpointer value,
    gsize size);
G_GNUC_INTERNAL sqInt gum_pharo_return_utf8 (const gchar * value);
G_GNUC_INTERNAL sqInt gum_pharo_return_nil (void);
G_GNUC_INTERNAL sqInt gum_pharo_fail_bad_argument (void);

G_GNUC_INTERNAL void gum_pharo_array_new (gsize size);
G_GNUC_INTERNAL void gum_pharo_array_put_string (gsize index,
    const gchar * value);
G_GNUC_INTERNAL void gum_pharo_array_put_utf8 (gsize index,
    const gchar * value);
G_GNUC_INTERNAL void gum_pharo_array_put_integer (gsize index, guint64 value);
G_GNUC_INTERNAL void gum_pharo_array_put_signed (gsize index, gint64 value);
G_GNUC_INTERNAL sqInt gum_pharo_array_return (void);

G_GNUC_INTERNAL sqInt prim_gum_pharo_listener_new (void);
G_GNUC_INTERNAL sqInt prim_gum_pharo_post (void);
G_GNUC_INTERNAL sqInt prim_gum_pharo_take_message (void);
G_GNUC_INTERNAL sqInt prim_gum_pharo_message_payload (void);
G_GNUC_INTERNAL sqInt prim_gum_pharo_message_data (void);
G_GNUC_INTERNAL sqInt prim_gum_pharo_release_message (void);
G_GNUC_INTERNAL sqInt prim_gum_pharo_set_message_semaphore (void);

G_END_DECLS

#endif
