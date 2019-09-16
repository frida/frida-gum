#ifndef __G_LIB_H__
#define __G_LIB_H__

#include <stdarg.h>
#include <stddef.h>

#define G_BEGIN_DECLS
#define G_END_DECLS

typedef void * gpointer;
typedef const void * gconstpointer;

typedef ssize_t gssize;
typedef size_t gsize;

typedef int gint;
typedef unsigned int guint;

typedef int8_t gint8;
typedef uint8_t guint8;

typedef int16_t gint16;
typedef uint16_t guint16;

typedef int32_t gint32;
typedef uint32_t guint32;

typedef int64_t gint64;
typedef uint64_t guint64;

typedef char gchar;
typedef unsigned char guchar;

typedef guint32 gunichar;
typedef guint16 gunichar2;

typedef gint gboolean;

typedef void (* GCallback) (void);
typedef void (* GDestroyNotify) (gpointer data);
typedef gint (* GCompareDataFunc) (gconstpointer a, gconstpointer b,
    gpointer user_data);

gchar * g_strdup (const gchar * str);
gchar * g_strdup_printf (const gchar * format, ...);
gchar * g_strdup_vprintf (const gchar * format, va_list args);
gboolean g_str_has_prefix (const gchar * str, const gchar * prefix);
gboolean g_str_has_suffix (const gchar * str, const gchar * suffix);

#define g_new(struct_type, n_structs) \
    g_malloc (n_structs * sizeof (struct_type))
#define g_new0(struct_type, n_structs) \
    g_malloc0 (n_structs * sizeof (struct_type))
#define g_renew(struct_type, mem, n_structs) \
    g_realloc (mem, n_structs * sizeof (struct_type))
gpointer g_malloc (gsize n_bytes);
gpointer g_malloc0 (gsize n_bytes);
gpointer g_realloc (gpointer mem, gsize n_bytes);
gpointer g_memdup (gconstpointer mem, guint byte_size);
void g_free (gpointer mem);

typedef struct _GThread GThread;

typedef gpointer (* GThreadFunc) (gpointer data);
GThread * g_thread_new (const gchar * name, GThreadFunc func,
    gpointer data);
gpointer g_thread_join (GThread * thread);
GThread * g_thread_ref (GThread * thread);
void g_thread_unref (GThread * thread);
void g_thread_yield (void);

typedef union _GMutex GMutex;
typedef struct _GCond GCond;

union _GMutex
{
  gpointer p;
  guint i[2];
};

struct _GCond
{
  gpointer p;
  guint i[2];
};

void g_mutex_init (GMutex * mutex);
void g_mutex_clear (GMutex * mutex);
void g_mutex_lock (GMutex * mutex);
void g_mutex_unlock (GMutex * mutex);
gboolean g_mutex_trylock (GMutex * mutex);

void g_cond_init (GCond * cond);
void g_cond_clear (GCond * cond);
void g_cond_wait (GCond * cond, GMutex * mutex);
void g_cond_signal (GCond * cond);
void g_cond_broadcast (GCond * cond);

gint g_atomic_int_add (volatile gint * atomic, gint val);
gssize g_atomic_pointer_add (volatile void * atomic, gssize val);

typedef struct _GString GString;

struct _GString
{
  gchar * str;
  gsize len;
  gsize allocated_len;
};

GString * g_string_new (const gchar * init);
GString * g_string_new_len (const gchar * init, gssize len);
GString * g_string_sized_new (gsize dfl_size);
gchar * g_string_free (GString * string, gboolean free_segment);
gboolean g_string_equal (const GString * v, const GString * v2);
guint g_string_hash (const GString * str);
GString * g_string_assign (GString * string, const gchar * rval);
GString * g_string_truncate (GString * string, gsize len);
GString * g_string_set_size (GString * string, gsize len);
GString * g_string_insert_len (GString * string, gssize pos, const gchar * val,
    gssize len);
GString * g_string_append (GString * string, const gchar * val);
GString * g_string_append_len (GString * string, const gchar * val, gssize len);
GString * g_string_append_c (GString * string, gchar c);
GString * g_string_append_unichar (GString * string, gunichar wc);
GString * g_string_prepend (GString * string, const gchar * val);
GString * g_string_prepend_c (GString * string, gchar c);
GString * g_string_prepend_unichar (GString * string, gunichar wc);
GString * g_string_prepend_len (GString * string, const gchar * val,
    gssize len);
GString * g_string_insert (GString * string, gssize pos, const gchar * val);
GString * g_string_insert_c (GString * string, gssize pos, gchar c);
GString * g_string_insert_unichar (GString * string, gssize pos, gunichar wc);
GString * g_string_overwrite (GString * string, gsize pos, const gchar * val);
GString * g_string_overwrite_len (GString * string, gsize pos,
    const gchar * val, gssize len);
GString * g_string_erase (GString * string, gssize pos, gssize len);
GString * g_string_ascii_down (GString * string);
GString * g_string_ascii_up (GString * string);
void g_string_vprintf (GString * string, const gchar * format, va_list args);
void g_string_printf (GString * string, const gchar * format, ...);
void g_string_append_vprintf (GString * string, const gchar * format,
    va_list args);
void g_string_append_printf (GString * string, const gchar * format, ...);

typedef struct _GArray GArray;

struct _GArray
{
  gchar * data;
  guint len;
};

#define g_array_append_val(a,v) g_array_append_vals (a, &(v), 1)
#define g_array_prepend_val(a,v) g_array_prepend_vals (a, &(v), 1)
#define g_array_insert_val(a, i, v) g_array_insert_vals (a, i, &(v), 1)
#define g_array_index(a, t, i) (((t *) (void *) (a)->data) [(i)])

GArray * g_array_new (gboolean zero_terminated, gboolean clear_,
    guint element_size);
GArray * g_array_sized_new (gboolean zero_terminated, gboolean clear_,
    guint element_size, guint reserved_size);
gchar * g_array_free (GArray * array, gboolean free_segment);
GArray * g_array_ref (GArray * array);
void g_array_unref (GArray * array);
guint g_array_get_element_size (GArray * array);
GArray * g_array_append_vals (GArray * array, gconstpointer data, guint len);
GArray * g_array_prepend_vals (GArray * array, gconstpointer data, guint len);
GArray * g_array_insert_vals (GArray * array, guint index_, gconstpointer data,
    guint len);
GArray * g_array_set_size (GArray * array, guint length);
GArray * g_array_remove_index (GArray * array, guint index_);
GArray * g_array_remove_index_fast (GArray * array, guint index_);
GArray * g_array_remove_range (GArray * array, guint index_, guint length);
void g_array_sort_with_data (GArray * array, GCompareDataFunc compare_func,
    gpointer user_data);
void g_array_set_clear_func (GArray * array, GDestroyNotify clear_func);

typedef struct _GHashTable GHashTable;
typedef struct _GHashTableIter GHashTableIter;

typedef guint (* GHashFunc) (gconstpointer key);
typedef gboolean (* GEqualFunc) (gconstpointer a, gconstpointer b);

struct _GHashTableIter
{
  gpointer dummy1;
  gpointer dummy2;
  gpointer dummy3;
  int dummy4;
  gboolean dummy5;
  gpointer dummy6;
};

GHashTable * g_hash_table_new_full (GHashFunc hash_func,
    GEqualFunc key_equal_func, GDestroyNotify key_destroy_func,
    GDestroyNotify value_destroy_func);
gboolean g_hash_table_insert (GHashTable * hash_table, gpointer key,
    gpointer value);
gboolean g_hash_table_replace (GHashTable * hash_table, gpointer key,
    gpointer value);
gboolean g_hash_table_add (GHashTable * hash_table, gpointer key);
gboolean g_hash_table_remove (GHashTable * hash_table, gconstpointer key);
void g_hash_table_remove_all (GHashTable * hash_table);
gpointer g_hash_table_lookup (GHashTable * hash_table, gconstpointer key);
gboolean g_hash_table_contains (GHashTable * hash_table, gconstpointer key);
gboolean g_hash_table_lookup_extended (GHashTable * hash_table,
    gconstpointer lookup_key, gpointer * orig_key, gpointer * value);
guint g_hash_table_size (GHashTable * hash_table);

void g_hash_table_iter_init (GHashTableIter * iter, GHashTable * hash_table);
gboolean g_hash_table_iter_next (GHashTableIter * iter, gpointer * key,
    gpointer * value);
GHashTable * g_hash_table_iter_get_hash_table (GHashTableIter * iter);
void g_hash_table_iter_remove (GHashTableIter * iter);
void g_hash_table_iter_replace (GHashTableIter * iter, gpointer value);
void g_hash_table_iter_steal (GHashTableIter * iter);

GHashTable * g_hash_table_ref (GHashTable * hash_table);
void g_hash_table_unref (GHashTable * hash_table);

gboolean g_str_equal (gconstpointer v1, gconstpointer v2);
guint g_str_hash (gconstpointer v);

gboolean g_int_equal (gconstpointer v1, gconstpointer v2);
guint g_int_hash (gconstpointer v);

gboolean g_int64_equal (gconstpointer v1, gconstpointer v2);
guint g_int64_hash (gconstpointer v);

gboolean g_double_equal (gconstpointer v1, gconstpointer v2);
guint g_double_hash (gconstpointer v);

guint g_direct_hash (gconstpointer v);
gboolean g_direct_equal (gconstpointer v1, gconstpointer v2);

#endif
