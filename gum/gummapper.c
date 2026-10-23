/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummapper.h"

#include "gumelfmapper.h"
#ifdef HAVE_WINDOWS
# include "gum/gumpemapper.h"
#endif
#ifdef HAVE_DARWIN
# include "gum/gumdarwinmoduleresolver.h"
# include "gum/gummachomapper.h"
#endif

typedef struct _GumMapperBackend GumMapperBackend;

struct _GumMapperBackend
{
  gpointer (* new_take_blob) (const gchar * name, GBytes * blob,
      GumModuleResolver * resolver, GError ** error);
  gpointer (* new_from_file) (const gchar * path, GumModuleResolver * resolver,
      GError ** error);
  gboolean (* load) (gpointer impl, GError ** error);
  void (* set_target) (gpointer impl, GumProcessMemory * target);
  void (* add_apple_parameter) (gpointer impl, const gchar * key,
      const gchar * value);
  gsize (* size) (gpointer impl);
  gboolean (* map) (gpointer impl, GumAddress base_address, GError ** error);
  GumAddress (* constructor) (gpointer impl);
  GumAddress (* destructor) (gpointer impl);
  GumAddress (* resolve) (gpointer impl, const gchar * symbol);
  void (* free) (gpointer impl);
};

struct _GumMapper
{
  GObject parent;

  const GumMapperBackend * backend;
  gpointer impl;
};

static void gum_mapper_dispose (GObject * object);
static const GumMapperBackend * gum_mapper_backend_for_magic (
    const guint8 * magic, gsize size);

G_DEFINE_TYPE (GumMapper, gum_mapper, G_TYPE_OBJECT)

static void
gum_mapper_class_init (GumMapperClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_mapper_dispose;
}

static void
gum_mapper_init (GumMapper * self)
{
}

static void
gum_mapper_dispose (GObject * object)
{
  GumMapper * self = GUM_MAPPER (object);

  g_clear_pointer (&self->impl, self->backend->free);

  G_OBJECT_CLASS (gum_mapper_parent_class)->dispose (object);
}

GumMapper *
gum_mapper_new_from_file (const gchar * path,
                          GumModuleResolver * resolver,
                          GError ** error)
{
  GumMapper * mapper;
  FILE * file;
  guint8 magic[4];
  gsize n;
  const GumMapperBackend * backend;
  gpointer impl;

  file = fopen (path, "rb");
  if (file == NULL)
    goto open_failed;
  n = fread (magic, sizeof (magic), 1, file);
  fclose (file);
  if (n != 1)
    goto unsupported_format;

  backend = gum_mapper_backend_for_magic (magic, sizeof (magic));
  if (backend == NULL)
    goto unsupported_format;

  impl = backend->new_from_file (path, resolver, error);
  if (impl == NULL)
    return NULL;

  mapper = g_object_new (GUM_TYPE_MAPPER, NULL);
  mapper->backend = backend;
  mapper->impl = impl;

  return mapper;

open_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Unable to open '%s'", path);
    return NULL;
  }
unsupported_format:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "Unsupported executable format");
    return NULL;
  }
}

GumMapper *
gum_mapper_new_take_blob (const gchar * name,
                          GBytes * blob,
                          GumModuleResolver * resolver,
                          GError ** error)
{
  GumMapper * mapper;
  gsize size;
  gconstpointer data;
  const GumMapperBackend * backend;
  gpointer impl;

  data = g_bytes_get_data (blob, &size);

  backend = gum_mapper_backend_for_magic (data, size);
  if (backend == NULL)
    goto unsupported_format;

  impl = backend->new_take_blob (name, blob, resolver, error);
  if (impl == NULL)
    return NULL;

  mapper = g_object_new (GUM_TYPE_MAPPER, NULL);
  mapper->backend = backend;
  mapper->impl = impl;

  return mapper;

unsupported_format:
  {
    g_bytes_unref (blob);
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "Unsupported executable format");
    return NULL;
  }
}

gboolean
gum_mapper_load (GumMapper * self,
                 GError ** error)
{
  return self->backend->load (self->impl, error);
}

void
gum_mapper_set_target (GumMapper * self,
                       GumProcessMemory * target)
{
  if (self->backend->set_target != NULL)
    self->backend->set_target (self->impl, target);
}

void
gum_mapper_add_apple_parameter (GumMapper * self,
                                const gchar * key,
                                const gchar * value)
{
  self->backend->add_apple_parameter (self->impl, key, value);
}

gsize
gum_mapper_size (GumMapper * self)
{
  return self->backend->size (self->impl);
}

gboolean
gum_mapper_map (GumMapper * self,
                GumAddress base_address,
                GError ** error)
{
  return self->backend->map (self->impl, base_address, error);
}

GumAddress
gum_mapper_constructor (GumMapper * self)
{
  return self->backend->constructor (self->impl);
}

GumAddress
gum_mapper_destructor (GumMapper * self)
{
  return self->backend->destructor (self->impl);
}

GumAddress
gum_mapper_resolve (GumMapper * self,
                    const gchar * symbol)
{
  return self->backend->resolve (self->impl, symbol);
}

#ifdef HAVE_DARWIN

static gpointer
gum_macho_mapper_backend_new_take_blob (const gchar * name,
                                        GBytes * blob,
                                        GumModuleResolver * resolver,
                                        GError ** error)
{
  return gum_macho_mapper_new_take_blob (name, blob,
      GUM_DARWIN_MODULE_RESOLVER (resolver), error);
}

static gpointer
gum_macho_mapper_backend_new_from_file (const gchar * path,
                                        GumModuleResolver * resolver,
                                        GError ** error)
{
  return gum_macho_mapper_new_from_file (path,
      GUM_DARWIN_MODULE_RESOLVER (resolver), error);
}

static gboolean
gum_macho_mapper_backend_load (gpointer impl,
                               GError ** error)
{
  return gum_macho_mapper_load (impl, error);
}

static void
gum_macho_mapper_backend_add_apple_parameter (gpointer impl,
                                              const gchar * key,
                                              const gchar * value)
{
  gum_macho_mapper_add_apple_parameter (impl, key, value);
}

static gsize
gum_macho_mapper_backend_size (gpointer impl)
{
  return gum_macho_mapper_size (impl);
}

static gboolean
gum_macho_mapper_backend_map (gpointer impl,
                              GumAddress base_address,
                              GError ** error)
{
  return gum_macho_mapper_map (impl, base_address, error);
}

static GumAddress
gum_macho_mapper_backend_constructor (gpointer impl)
{
  return gum_macho_mapper_constructor (impl);
}

static GumAddress
gum_macho_mapper_backend_destructor (gpointer impl)
{
  return gum_macho_mapper_destructor (impl);
}

static GumAddress
gum_macho_mapper_backend_resolve (gpointer impl,
                                  const gchar * symbol)
{
  return gum_macho_mapper_resolve (impl, symbol);
}

static void
gum_macho_mapper_backend_free (gpointer impl)
{
  g_object_unref (impl);
}

static const GumMapperBackend gum_macho_mapper_backend =
{
  gum_macho_mapper_backend_new_take_blob,
  gum_macho_mapper_backend_new_from_file,
  gum_macho_mapper_backend_load,
  NULL,
  gum_macho_mapper_backend_add_apple_parameter,
  gum_macho_mapper_backend_size,
  gum_macho_mapper_backend_map,
  gum_macho_mapper_backend_constructor,
  gum_macho_mapper_backend_destructor,
  gum_macho_mapper_backend_resolve,
  gum_macho_mapper_backend_free,
};

#endif

#ifdef HAVE_WINDOWS

static gpointer
gum_pe_mapper_backend_new_take_blob (const gchar * name,
                                     GBytes * blob,
                                     GumModuleResolver * resolver,
                                     GError ** error)
{
  return gum_pe_mapper_new_take_blob (name, blob, resolver, error);
}

static gpointer
gum_pe_mapper_backend_new_from_file (const gchar * path,
                                     GumModuleResolver * resolver,
                                     GError ** error)
{
  return gum_pe_mapper_new_from_file (path, resolver, error);
}

static gboolean
gum_pe_mapper_backend_load (gpointer impl,
                            GError ** error)
{
  return gum_pe_mapper_load (impl, error);
}

static void
gum_pe_mapper_backend_set_target (gpointer impl,
                                  GumProcessMemory * target)
{
  gum_pe_mapper_set_target (impl, target);
}

static void
gum_pe_mapper_backend_add_apple_parameter (gpointer impl,
                                           const gchar * key,
                                           const gchar * value)
{
}

static gsize
gum_pe_mapper_backend_size (gpointer impl)
{
  return gum_pe_mapper_size (impl);
}

static gboolean
gum_pe_mapper_backend_map (gpointer impl,
                           GumAddress base_address,
                           GError ** error)
{
  return gum_pe_mapper_map (impl, base_address, error);
}

static GumAddress
gum_pe_mapper_backend_constructor (gpointer impl)
{
  return gum_pe_mapper_constructor (impl);
}

static GumAddress
gum_pe_mapper_backend_destructor (gpointer impl)
{
  return gum_pe_mapper_destructor (impl);
}

static GumAddress
gum_pe_mapper_backend_resolve (gpointer impl,
                               const gchar * symbol)
{
  return gum_pe_mapper_resolve (impl, symbol);
}

static void
gum_pe_mapper_backend_free (gpointer impl)
{
  g_object_unref (impl);
}

static const GumMapperBackend gum_pe_mapper_backend =
{
  gum_pe_mapper_backend_new_take_blob,
  gum_pe_mapper_backend_new_from_file,
  gum_pe_mapper_backend_load,
  gum_pe_mapper_backend_set_target,
  gum_pe_mapper_backend_add_apple_parameter,
  gum_pe_mapper_backend_size,
  gum_pe_mapper_backend_map,
  gum_pe_mapper_backend_constructor,
  gum_pe_mapper_backend_destructor,
  gum_pe_mapper_backend_resolve,
  gum_pe_mapper_backend_free,
};

#endif

static gpointer
gum_elf_mapper_backend_new_take_blob (const gchar * name,
                                      GBytes * blob,
                                      GumModuleResolver * resolver,
                                      GError ** error)
{
  return gum_elf_mapper_new_take_blob (name, blob, resolver, error);
}

static gpointer
gum_elf_mapper_backend_new_from_file (const gchar * path,
                                      GumModuleResolver * resolver,
                                      GError ** error)
{
  return gum_elf_mapper_new_from_file (path, resolver, error);
}

static gboolean
gum_elf_mapper_backend_load (gpointer impl,
                             GError ** error)
{
  return gum_elf_mapper_load (impl, error);
}

static void
gum_elf_mapper_backend_set_target (gpointer impl,
                                   GumProcessMemory * target)
{
  gum_elf_mapper_set_target (impl, target);
}

static void
gum_elf_mapper_backend_add_apple_parameter (gpointer impl,
                                            const gchar * key,
                                            const gchar * value)
{
}

static gsize
gum_elf_mapper_backend_size (gpointer impl)
{
  return gum_elf_mapper_size (impl);
}

static gboolean
gum_elf_mapper_backend_map (gpointer impl,
                            GumAddress base_address,
                            GError ** error)
{
  return gum_elf_mapper_map (impl, base_address, error);
}

static GumAddress
gum_elf_mapper_backend_constructor (gpointer impl)
{
  return gum_elf_mapper_constructor (impl);
}

static GumAddress
gum_elf_mapper_backend_destructor (gpointer impl)
{
  return gum_elf_mapper_destructor (impl);
}

static GumAddress
gum_elf_mapper_backend_resolve (gpointer impl,
                                const gchar * symbol)
{
  return gum_elf_mapper_resolve (impl, symbol);
}

static void
gum_elf_mapper_backend_free (gpointer impl)
{
  g_object_unref (impl);
}

static const GumMapperBackend gum_elf_mapper_backend =
{
  gum_elf_mapper_backend_new_take_blob,
  gum_elf_mapper_backend_new_from_file,
  gum_elf_mapper_backend_load,
  gum_elf_mapper_backend_set_target,
  gum_elf_mapper_backend_add_apple_parameter,
  gum_elf_mapper_backend_size,
  gum_elf_mapper_backend_map,
  gum_elf_mapper_backend_constructor,
  gum_elf_mapper_backend_destructor,
  gum_elf_mapper_backend_resolve,
  gum_elf_mapper_backend_free,
};

static const GumMapperBackend *
gum_mapper_backend_for_magic (const guint8 * magic,
                              gsize size)
{
  if (size < 4)
    return NULL;

#ifdef HAVE_DARWIN
  if (magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba &&
      magic[3] == 0xbe)
    return &gum_macho_mapper_backend;
  if (magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa &&
      (magic[3] == 0xce || magic[3] == 0xcf))
    return &gum_macho_mapper_backend;
  if (magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed &&
      magic[3] == 0xfe)
    return &gum_macho_mapper_backend;
#endif
#ifdef HAVE_WINDOWS
  if (magic[0] == 'M' && magic[1] == 'Z')
    return &gum_pe_mapper_backend;
#endif

  if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' &&
      magic[3] == 'F')
    return &gum_elf_mapper_backend;

  return NULL;
}
