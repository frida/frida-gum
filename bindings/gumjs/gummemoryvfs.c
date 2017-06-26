/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemoryvfs.h"

#include <gio/gio.h>
#include <string.h>

#define GUM_MEMORY_VFS(vfs) ((GumMemoryVfs *) (vfs))
#define GUM_MEMORY_FILE(f) ((GumMemoryFile *) (f))

typedef struct _GumMemoryFile GumMemoryFile;
typedef struct _GumMemoryFileEntry GumMemoryFileEntry;

typedef void (* GumDlFunc) (void);

struct _GumMemoryFile
{
  sqlite3_file file;
  GumMemoryFileEntry * entry;
};

struct _GumMemoryFileEntry
{
  guint ref_count;
  guint8 * data;
  gsize size;
  gint lock_level;
};

static GumMemoryFileEntry * gum_memory_vfs_add_entry (GumMemoryVfs * self,
    gchar * path, guint8 * data, gsize size);
static int gum_memory_vfs_open (sqlite3_vfs * vfs, const char * name,
    sqlite3_file * file, int flags, int * out_flags);
static int gum_memory_vfs_delete (sqlite3_vfs * vfs, const char * name,
    int sync_dir);
static int gum_memory_vfs_access (sqlite3_vfs * vfs, const char * name,
    int flags, int * res_out);
static int gum_memory_vfs_full_pathname (sqlite3_vfs * vfs, const char * name,
    int n_out, char * z_out);
static void * gum_memory_vfs_dlopen (sqlite3_vfs * vfs, const char * filename);
static void gum_memory_vfs_dlerror (sqlite3_vfs * vfs, int n_bytes,
    char * error_message);
static GumDlFunc gum_memory_vfs_dlsym (sqlite3_vfs * vfs, void * module,
    const char * symbol);
static void gum_memory_vfs_dlclose (sqlite3_vfs * vfs, void * module);
static int gum_memory_vfs_randomness (sqlite3_vfs * vfs, int n_bytes,
    char * z_out);
static int gum_memory_vfs_sleep (sqlite3_vfs * vfs, int microseconds);
static int gum_memory_vfs_current_time (sqlite3_vfs * vfs, double * t);
static int gum_memory_vfs_current_time_int64 (sqlite3_vfs * vfs,
    sqlite3_int64 * t);

static GumMemoryFileEntry * gum_memory_file_entry_ref (
    GumMemoryFileEntry * self);
static void gum_memory_file_entry_unref (GumMemoryFileEntry * self);
static int gum_memory_file_close (sqlite3_file * file);
static int gum_memory_file_read (sqlite3_file * file, void * buffer, int amount,
    sqlite3_int64 offset);
static int gum_memory_file_write (sqlite3_file * file, const void * buffer,
    int amount, sqlite3_int64 offset);
static int gum_memory_file_truncate (sqlite3_file * file, sqlite3_int64 size);
static int gum_memory_file_sync (sqlite3_file * file, int flags);
static int gum_memory_file_size (sqlite3_file * file, sqlite3_int64 * size);
static int gum_memory_file_lock (sqlite3_file * file, int level);
static int gum_memory_file_unlock (sqlite3_file * file, int level);
static int gum_memory_file_check_reserved_lock (sqlite3_file * file,
    int * result);
static int gum_memory_file_control (sqlite3_file * file, int op, void * arg);
static int gum_memory_file_sector_size (sqlite3_file * file);
static int gum_memory_file_device_characteristics (sqlite3_file * file);
static int gum_memory_file_shm_map (sqlite3_file * file, int region,
    int region_size, int extend, void volatile ** memory);
static int gum_memory_file_shm_lock (sqlite3_file * file, int offset, int n,
    int flags);
static void gum_memory_file_shm_barrier (sqlite3_file * file);
static int gum_memory_file_shm_unmap (sqlite3_file * file, int delete_flag);
static int gum_memory_file_fetch (sqlite3_file * file, sqlite3_int64 offset,
    int amount, void ** memory);
static int gum_memory_file_unfetch (sqlite3_file * file, sqlite3_int64 offset,
    void * memory);

static gint gum_vfs_next_id = 1;

static const sqlite3_io_methods gum_memory_file_methods = {
  3,

  gum_memory_file_close,
  gum_memory_file_read,
  gum_memory_file_write,
  gum_memory_file_truncate,
  gum_memory_file_sync,
  gum_memory_file_size,
  gum_memory_file_lock,
  gum_memory_file_unlock,
  gum_memory_file_check_reserved_lock,
  gum_memory_file_control,
  gum_memory_file_sector_size,
  gum_memory_file_device_characteristics,

  gum_memory_file_shm_map,
  gum_memory_file_shm_lock,
  gum_memory_file_shm_barrier,
  gum_memory_file_shm_unmap,

  gum_memory_file_fetch,
  gum_memory_file_unfetch
};

GumMemoryVfs *
gum_memory_vfs_new (void)
{
  GumMemoryVfs * self;
  sqlite3_vfs * vfs;

  self = g_slice_new0 (GumMemoryVfs);

  self->name = g_strdup_printf ("gum-%d",
      g_atomic_int_add (&gum_vfs_next_id, 1));
  self->default_vfs = sqlite3_vfs_find (NULL);
  self->entries = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) gum_memory_file_entry_unref);
  self->next_entry_id = 1;

  vfs = &self->vfs;

  vfs->iVersion = 3;
  vfs->szOsFile = sizeof (GumMemoryFile);
  vfs->mxPathname = self->default_vfs->mxPathname;
  vfs->zName = self->name;

  vfs->xOpen = gum_memory_vfs_open;
  vfs->xDelete = gum_memory_vfs_delete;
  vfs->xAccess = gum_memory_vfs_access;
  vfs->xFullPathname = gum_memory_vfs_full_pathname;
  vfs->xDlOpen = gum_memory_vfs_dlopen;
  vfs->xDlError = gum_memory_vfs_dlerror;
  vfs->xDlSym = gum_memory_vfs_dlsym;
  vfs->xDlClose = gum_memory_vfs_dlclose;
  vfs->xRandomness = gum_memory_vfs_randomness;
  vfs->xSleep = gum_memory_vfs_sleep;
  vfs->xCurrentTime = gum_memory_vfs_current_time;

  vfs->xCurrentTimeInt64 = gum_memory_vfs_current_time_int64;

  return self;
}

void
gum_memory_vfs_free (GumMemoryVfs * self)
{
  g_hash_table_unref (self->entries);
  g_free (self->name);

  g_slice_free (GumMemoryVfs, self);
}

const gchar *
gum_memory_vfs_add_file (GumMemoryVfs * self,
                         gpointer contents,
                         gsize size)
{
  gchar * path;

  path = g_strdup_printf ("/f%d.db", self->next_entry_id++);

  gum_memory_vfs_add_entry (self, path, contents, size);

  return path;
}

void
gum_memory_vfs_remove_file (GumMemoryVfs * self,
                            const gchar * path)
{
  self->vfs.xDelete (&self->vfs, path, FALSE);
}

gboolean
gum_memory_vfs_get_file_contents (GumMemoryVfs * self,
                                  const gchar * path,
                                  gpointer * contents,
                                  gsize * size)
{
  GumMemoryFileEntry * entry;

  entry = g_hash_table_lookup (self->entries, path);
  if (entry == NULL)
    return FALSE;

  *contents = entry->data;
  *size = entry->size;

  return TRUE;
}

static GumMemoryFileEntry *
gum_memory_vfs_add_entry (GumMemoryVfs * self,
                          gchar * path,
                          guint8 * data,
                          gsize size)
{
  GumMemoryFileEntry * entry;

  entry = g_slice_new (GumMemoryFileEntry);
  entry->ref_count = 1;
  entry->data = data;
  entry->size = size;
  entry->lock_level = SQLITE_LOCK_NONE;
  g_hash_table_replace (self->entries, path, entry);

  return entry;
}

static int
gum_memory_vfs_open (sqlite3_vfs * vfs,
                     const char * name,
                     sqlite3_file * file,
                     int flags,
                     int * out_flags)
{
  GumMemoryVfs * self = GUM_MEMORY_VFS (vfs);
  GumMemoryFile * f = GUM_MEMORY_FILE (file);
  GumMemoryFileEntry * entry;

  memset (f, 0, sizeof (GumMemoryFile));

  if ((flags & SQLITE_OPEN_CREATE) != 0)
  {
    entry = gum_memory_vfs_add_entry (self, g_strdup (name), NULL, 0);
  }
  else
  {
    entry = g_hash_table_lookup (self->entries, name);
    if (entry == NULL)
      return SQLITE_CANTOPEN;
  }

  file->pMethods = &gum_memory_file_methods;

  f->entry = gum_memory_file_entry_ref (entry);

  if (out_flags != NULL)
    *out_flags = flags;

  return SQLITE_OK;
}

static int
gum_memory_vfs_delete (sqlite3_vfs * vfs,
                       const char * name,
                       int sync_dir)
{
  GumMemoryVfs * self = GUM_MEMORY_VFS (vfs);
  gboolean removed;

  removed = g_hash_table_remove (self->entries, name);

  return removed ? SQLITE_OK : SQLITE_IOERR_DELETE_NOENT;
}

static int
gum_memory_vfs_access (sqlite3_vfs * vfs,
                       const char * name,
                       int flags,
                       int * res_out)
{
  GumMemoryVfs * self = GUM_MEMORY_VFS (vfs);

  *res_out = g_hash_table_contains (self->entries, name);
  return SQLITE_OK;
}

static int
gum_memory_vfs_full_pathname (sqlite3_vfs * vfs,
                              const char * name,
                              int n_out,
                              char * z_out)
{
  gchar * full_path;
  gboolean buffer_too_small;

  full_path = (name[0] == '/')
      ? g_strdup (name)
      : g_strconcat ("/", name, NULL);

  g_strlcpy (z_out, full_path, n_out);
  buffer_too_small = strlen (full_path) >= (gsize) n_out;

  g_free (full_path);

  return buffer_too_small ? SQLITE_CANTOPEN : SQLITE_OK;
}

static void *
gum_memory_vfs_dlopen (sqlite3_vfs * vfs,
                       const char * filename)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xDlOpen (dvfs, filename);
}

static void
gum_memory_vfs_dlerror (sqlite3_vfs * vfs,
                        int n_bytes,
                        char * error_message)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  dvfs->xDlError (dvfs, n_bytes, error_message);
}

static GumDlFunc
gum_memory_vfs_dlsym (sqlite3_vfs * vfs,
                      void * module,
                      const char * symbol)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xDlSym (dvfs, module, symbol);
}

static void
gum_memory_vfs_dlclose (sqlite3_vfs * vfs,
                        void * module)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  dvfs->xDlClose (dvfs, module);
}

static int
gum_memory_vfs_randomness (sqlite3_vfs * vfs,
                           int n_bytes,
                           char * z_out)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xRandomness (dvfs, n_bytes, z_out);
}

static int
gum_memory_vfs_sleep (sqlite3_vfs * vfs,
                      int microseconds)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xSleep (dvfs, microseconds);
}

static int
gum_memory_vfs_current_time (sqlite3_vfs * vfs,
                             double * t)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xCurrentTime (dvfs, t);
}

static int
gum_memory_vfs_current_time_int64 (sqlite3_vfs * vfs,
                                   sqlite3_int64 * t)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xCurrentTimeInt64 (dvfs, t);
}

static GumMemoryFileEntry *
gum_memory_file_entry_ref (GumMemoryFileEntry * self)
{
  self->ref_count++;
  return self;
}

static void
gum_memory_file_entry_unref (GumMemoryFileEntry * self)
{
  if (--self->ref_count == 0)
  {
    g_free (self->data);

    g_slice_free (GumMemoryFileEntry, self);
  }
}

static int
gum_memory_file_close (sqlite3_file * file)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);

  gum_memory_file_entry_unref (self->entry);
  self->entry = NULL;

  return SQLITE_OK;
}

static int
gum_memory_file_read (sqlite3_file * file,
                      void * buffer,
                      int amount,
                      sqlite3_int64 offset)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);
  GumMemoryFileEntry * entry = self->entry;
  gint available, n;

  if (offset < 0 || (gsize) offset >= entry->size)
    return SQLITE_IOERR_READ;

  available = entry->size - offset;
  n = MIN (amount, available);

  memcpy (buffer, entry->data + offset, n);

  if (n < amount)
  {
    memset ((guint8 *) buffer + n, 0, amount - n);
    return SQLITE_IOERR_SHORT_READ;
  }

  return SQLITE_OK;
}

static int
gum_memory_file_write (sqlite3_file * file,
                       const void * buffer,
                       int amount,
                       sqlite3_int64 offset)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);
  GumMemoryFileEntry * entry = self->entry;
  gsize required_size;

  if (offset < 0)
    return SQLITE_IOERR_WRITE;

  required_size = offset + amount;
  if (required_size > entry->size)
  {
    entry->data = g_realloc (entry->data, required_size);
    entry->size = required_size;
  }

  memcpy (entry->data + offset, buffer, amount);

  return SQLITE_OK;
}

static int
gum_memory_file_truncate (sqlite3_file * file,
                          sqlite3_int64 size)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);
  GumMemoryFileEntry * entry = self->entry;

  g_free (g_steal_pointer (&entry->data));
  entry->size = 0;

  return SQLITE_OK;
}

static int
gum_memory_file_sync (sqlite3_file * file,
                      int flags)
{
  return SQLITE_OK;
}

static int
gum_memory_file_size (sqlite3_file * file,
                      sqlite3_int64 * size)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);

  *size = self->entry->size;
  return SQLITE_OK;
}

static int
gum_memory_file_lock (sqlite3_file * file,
                      int level)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);

  self->entry->lock_level = level;

  return SQLITE_OK;
}

static int
gum_memory_file_unlock (sqlite3_file * file,
                        int level)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);
  GumMemoryFileEntry * entry = self->entry;

  if (entry->lock_level < level)
    return SQLITE_OK;

  entry->lock_level = level;

  return SQLITE_OK;
}

static int
gum_memory_file_check_reserved_lock (sqlite3_file * file,
                                     int * result)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);

  *result = self->entry->lock_level > SQLITE_LOCK_SHARED;
  return SQLITE_OK;
}

static int
gum_memory_file_control (sqlite3_file * file,
                         int op,
                         void * arg)
{
  return SQLITE_NOTFOUND;
}

static int
gum_memory_file_sector_size (sqlite3_file * file)
{
  return 4096;
}

static int
gum_memory_file_device_characteristics (sqlite3_file * file)
{
  return SQLITE_IOCAP_ATOMIC |
      SQLITE_IOCAP_SAFE_APPEND |
      SQLITE_IOCAP_SEQUENTIAL |
      SQLITE_IOCAP_POWERSAFE_OVERWRITE;
}

static int
gum_memory_file_shm_map (sqlite3_file * file,
                         int region,
                         int region_size,
                         int extend,
                         void volatile ** memory)
{
  return SQLITE_IOERR_NOMEM;
}

static int
gum_memory_file_shm_lock (sqlite3_file * file,
                          int offset,
                          int n,
                          int flags)
{
  return SQLITE_OK;
}

static void
gum_memory_file_shm_barrier (sqlite3_file * file)
{
}

static int
gum_memory_file_shm_unmap (sqlite3_file * file,
                           int delete_flag)
{
  return SQLITE_OK;
}

static int
gum_memory_file_fetch (sqlite3_file * file,
                       sqlite3_int64 offset,
                       int amount,
                       void ** memory)
{
  *memory = NULL;
  return SQLITE_OK;
}

static int
gum_memory_file_unfetch (sqlite3_file * file,
                         sqlite3_int64 offset,
                         void * memory)
{
  return SQLITE_OK;
}

gchar *
gum_memory_vfs_contents_to_string (gconstpointer contents,
                                   gsize size)
{
  GOutputStream * sink, * source;
  GMemoryOutputStream * sink_memory;
  GConverter * compressor;
  gchar * encoded_contents;

  sink = g_memory_output_stream_new_resizable ();
  sink_memory = G_MEMORY_OUTPUT_STREAM (sink);
  compressor = G_CONVERTER (
      g_zlib_compressor_new (G_ZLIB_COMPRESSOR_FORMAT_GZIP, -1));
  source = g_converter_output_stream_new (sink, compressor);

  g_output_stream_write_all (source, contents, size, NULL, NULL, NULL);
  g_output_stream_flush (source, NULL, NULL);
  g_output_stream_close (source, NULL, NULL);

  encoded_contents = g_base64_encode (
      g_memory_output_stream_get_data (sink_memory),
      g_memory_output_stream_get_data_size (sink_memory));

  g_object_unref (source);
  g_object_unref (compressor);
  g_object_unref (sink);

  return encoded_contents;
}

gboolean
gum_memory_vfs_contents_from_string (const gchar * str,
                                     gpointer * contents,
                                     gsize * size)
{
  guchar * data;
  gsize data_size;
  gboolean is_compressed;
  guint8 * buffer = NULL;

  data = g_base64_decode (str, &data_size);
  if (data == NULL)
    goto invalid_base64;

  is_compressed = data_size >= 2 && data[0] == 0x1f && data[1] == 0x8b;
  if (is_compressed)
  {
    GConverter * converter;
    gsize buffer_size;
    gsize in_offset, out_offset;
    GError * error;
    GConverterResult result;

    converter = G_CONVERTER (
        g_zlib_decompressor_new (G_ZLIB_COMPRESSOR_FORMAT_GZIP));

    buffer_size = 4096;
    buffer = g_malloc (buffer_size);
    in_offset = 0;
    out_offset = 0;

    error = NULL;
    do
    {
      gsize bytes_read, bytes_written, remaining_capacity;

      result = g_converter_convert (converter, data + in_offset,
          data_size - in_offset, buffer + out_offset, buffer_size - out_offset,
          G_CONVERTER_INPUT_AT_END, &bytes_read, &bytes_written, &error);
      if (result == G_CONVERTER_ERROR)
        goto invalid_data;

      in_offset += bytes_read;
      out_offset += bytes_written;

      remaining_capacity = buffer_size - out_offset;
      if (remaining_capacity < 2048)
      {
        buffer_size *= 2;
        buffer = g_realloc (buffer, buffer_size);
      }
    }
    while (result != G_CONVERTER_FINISHED);

    g_free (data);
    data = g_steal_pointer (&buffer);
    data_size = out_offset;

    data = g_realloc (data, data_size);
  }

  *contents = data;
  *size = data_size;

  return TRUE;

invalid_base64:
  {
    return FALSE;
  }
invalid_data:
  {
    g_free (buffer);
    g_free (data);

    return FALSE;
  }
}
