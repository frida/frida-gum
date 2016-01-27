/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcodesegment.h"

#include "gumdarwin.h"

#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define GUM_CS_MAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define GUM_CS_MAGIC_CODE_DIRECTORY 0xfade0c02
#define GUM_CS_MAGIC_REQUIREMENTS 0xfade0c01

#define GUM_CS_HASH_SHA1 1
#define GUM_CS_HASH_SHA1_SIZE 20

typedef struct _GumCodeLayout GumCodeLayout;
typedef struct _GumCsSuperBlob GumCsSuperBlob;
typedef struct _GumCsBlobIndex GumCsBlobIndex;
typedef struct _GumCsDirectory GumCsDirectory;
typedef struct _GumCsRequirements GumCsRequirements;

struct _GumCodeSegment
{
  gpointer data;
  gsize size;

  gsize virtual_size;

  FILE * file;
  gint fd;
};

struct _GumCodeLayout
{
  gsize header_file_size;

  gsize text_file_offset;
  gsize text_file_size;
  gsize text_size;

  gsize code_signature_file_offset;
  gsize code_signature_file_size;
  gsize code_signature_page_size;
  gsize code_signature_size;
  gsize code_signature_hash_count;
  gsize code_signature_hash_size;
};

struct _GumCsBlobIndex
{
  guint32 type;
  guint32 offset;
};

struct _GumCsSuperBlob
{
  guint32 magic;
  guint32 length;
  guint32 count;
  GumCsBlobIndex index[];
};

struct _GumCsDirectory
{
  guint32 magic;
  guint32 length;
  guint32 version;
  guint32 flags;
  guint32 hash_offset;
  guint32 ident_offset;
  guint32 num_special_slots;
  guint32 num_code_slots;
  guint32 code_limit;
  guint8 hash_size;
  guint8 hash_type;
  guint8 reserved_1;
  guint8 page_size;
  guint32 reserved_2;
};

struct _GumCsRequirements
{
  guint32 magic;
  guint32 length;
  guint32 count;
};

static void gum_code_segment_compute_layout (GumCodeSegment * self,
    GumCodeLayout * layout);

static void gum_put_mach_headers (const gchar * dylib_path,
    const GumCodeLayout * layout, gpointer output, gsize * output_size);
static void gum_put_code_signature (gconstpointer header, gconstpointer text,
    const GumCodeLayout * layout, gpointer output);

GumCodeSegment *
gum_code_segment_new (gsize size)
{
  GumCodeSegment * segment;
  guint page_size, size_in_pages;

  segment = g_slice_new (GumCodeSegment);

  segment->data = mmap (NULL, size, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANON, -1, 0);
  segment->size = size;

  page_size = gum_query_page_size ();
  size_in_pages = size / page_size;
  if (size % page_size != 0)
    size_in_pages++;
  segment->virtual_size = size_in_pages * page_size;

  segment->file = NULL;
  segment->fd = -1;

  return segment;
}

void
gum_code_segment_free (GumCodeSegment * segment)
{
  if (segment->file != NULL)
    fclose (segment->file);

  munmap (segment->data, segment->size);

  g_slice_free (GumCodeSegment, segment);
}

gpointer
gum_code_segment_get_address (GumCodeSegment * self)
{
  return self->data;
}

void
gum_code_segment_realize (GumCodeSegment * self)
{
  const gchar * dylib_path;
  GumCodeLayout layout;
  guint8 * dylib_header;
  gsize dylib_header_size;
  guint8 * code_signature;

  /* TODO: generate */
  dylib_path = "/Library/Caches/frida-test.dylib";

  gum_code_segment_compute_layout (self, &layout);

  dylib_header = g_malloc0 (layout.header_file_size);
  gum_put_mach_headers (dylib_path, &layout, dylib_header, &dylib_header_size);

  code_signature = g_malloc0 (layout.code_signature_file_size);
  gum_put_code_signature (dylib_header, self->data, &layout, code_signature);

  {
    gint res;
    FILE * file;
    fsignatures_t sigs;

    self->fd = open (dylib_path, O_RDWR | O_CREAT | O_TRUNC);
    g_assert (self->fd != -1);
    self->file = file = fdopen (self->fd, "w");
    g_assert (self->file != NULL);

    fwrite (dylib_header, dylib_header_size, 1, file);

    fseek (file, layout.text_file_offset, SEEK_SET);
    fwrite (self->data, layout.text_size, 1, file);

    fseek (file, layout.code_signature_file_offset, SEEK_SET);
    fwrite (code_signature, layout.code_signature_file_size, 1, file);

    fflush (file);

    sigs.fs_file_start = 0;
    sigs.fs_blob_start = GSIZE_TO_POINTER (layout.code_signature_file_offset);
    sigs.fs_blob_size = layout.code_signature_file_size;

    res = fcntl (self->fd, F_ADDFILESIGS, &sigs);
    g_print ("fcntl(F_ADDFILESIGS) => %d\n", res);
  }

  g_free (code_signature);

  g_free (dylib_header);
}

void
gum_code_segment_map (GumCodeSegment * self,
                      gsize source_offset,
                      gsize source_size,
                      gpointer target_address)
{
  gpointer result;

  result = mmap (target_address, source_size, PROT_READ | PROT_EXEC,
      MAP_PRIVATE | MAP_FIXED, self->fd,
      gum_query_page_size () + source_offset);
  g_assert (result != MAP_FAILED);
}

static void
gum_code_segment_compute_layout (GumCodeSegment * self,
                                 GumCodeLayout * layout)
{
  gsize page_size, cs_page_size, cs_hash_count, cs_hash_size;
  gsize cs_size, cs_file_size;

  page_size = gum_query_page_size ();

  layout->header_file_size = page_size;

  layout->text_file_offset = layout->header_file_size;
  layout->text_file_size = self->virtual_size;
  layout->text_size = self->size;

  cs_page_size = 4096;
  cs_hash_count =
      (layout->text_file_offset + layout->text_file_size) / cs_page_size;
  cs_hash_size = GUM_CS_HASH_SHA1_SIZE;

  cs_size = 125 + (cs_hash_count * cs_hash_size);
  cs_file_size = cs_size;
  if (cs_file_size % 4 != 0)
    cs_file_size += 4 - (cs_file_size % 4);

  layout->code_signature_file_offset =
      layout->text_file_offset + layout->text_file_size;
  layout->code_signature_file_size = cs_file_size;
  layout->code_signature_page_size = cs_page_size;
  layout->code_signature_size = cs_size;
  layout->code_signature_hash_count = cs_hash_count;
  layout->code_signature_hash_size = cs_hash_size;
}

static void
gum_put_mach_headers (const gchar * dylib_path,
                      const GumCodeLayout * layout,
                      gpointer output,
                      gsize * output_size)
{
  gsize dylib_path_size;
  gum_mach_header_t * header = output;
  gum_segment_command_t * seg, * text_segment, * linkedit_segment;
  gum_section_t * sect;
  struct dylib_command * dl;
  struct linkedit_data_command * sig;

  dylib_path_size = strlen (dylib_path);

  if (sizeof (gpointer) == 4)
  {
    header->magic = MH_MAGIC;
    header->cputype = CPU_TYPE_ARM;
    header->cpusubtype = CPU_SUBTYPE_UVAXII;
  }
  else
  {
    header->magic = MH_MAGIC_64;
    header->cputype = CPU_TYPE_ARM64;
    header->cpusubtype = CPU_SUBTYPE_LITTLE_ENDIAN;
  }
  header->filetype = MH_DYLIB;
  header->ncmds = 5;
  header->flags = MH_DYLDLINK | MH_PIE;

  seg = (gum_segment_command_t *) (header + 1);
  seg->cmd = GUM_LC_SEGMENT;
  seg->cmdsize = sizeof (gum_segment_command_t);
  strcpy (seg->segname, SEG_PAGEZERO);
  seg->vmaddr = 0;
  seg->vmsize = gum_query_page_size ();
  seg->fileoff = 0;
  seg->filesize = 0;
  seg->maxprot = PROT_NONE;
  seg->initprot = PROT_NONE;
  seg->nsects = 0;
  seg->flags = 0;

  seg++;
  seg->cmd = GUM_LC_SEGMENT;
  seg->cmdsize =
      sizeof (gum_segment_command_t) + sizeof (gum_section_t);
  strcpy (seg->segname, SEG_TEXT);
  seg->vmaddr = layout->text_file_offset;
  seg->vmsize = layout->text_file_size;
  seg->fileoff = layout->text_file_offset;
  seg->filesize = layout->text_file_size;
  seg->maxprot = PROT_READ | PROT_WRITE | PROT_EXEC;
  seg->initprot = PROT_READ | PROT_EXEC;
  seg->nsects = 1;
  seg->flags = 0;
  sect = (gum_section_t *) (seg + 1);
  strcpy (sect->sectname, SECT_TEXT);
  strcpy (sect->segname, SEG_TEXT);
  sect->addr = layout->text_file_offset;
  sect->size = layout->text_size;
  sect->offset = layout->text_file_offset;
  sect->align = 4;
  sect->reloff = 0;
  sect->nreloc = 0;
  sect->flags =
      S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
  text_segment = seg;

  seg = (gum_segment_command_t *) (sect + 1);
  seg->cmd = GUM_LC_SEGMENT;
  seg->cmdsize = sizeof (gum_segment_command_t);
  strcpy (seg->segname, SEG_LINKEDIT);
  seg->vmaddr = text_segment->vmaddr + text_segment->vmsize;
  seg->vmsize = 4096;
  seg->fileoff = layout->code_signature_file_offset;
  seg->filesize = layout->code_signature_file_size;
  seg->maxprot = PROT_READ;
  seg->initprot = PROT_READ;
  seg->nsects = 0;
  seg->flags = 0;
  linkedit_segment = seg;

  dl = (struct dylib_command *) (seg + 1);
  dl->cmd = LC_ID_DYLIB;
  dl->cmdsize = sizeof (struct dylib_command) + dylib_path_size;
  if ((dl->cmdsize % 4) != 0)
    dl->cmdsize += 4 - (dl->cmdsize % 4);
  dl->dylib.name.offset = sizeof (struct dylib_command);
  dl->dylib.timestamp = 0;
  dl->dylib.current_version = 0;
  dl->dylib.compatibility_version = 0;
  memcpy ((gchar *) (dl + 1), dylib_path, dylib_path_size);

  sig = (struct linkedit_data_command *) (((guint8 *) dl) + dl->cmdsize);
  sig->cmd = LC_CODE_SIGNATURE;
  sig->cmdsize = sizeof (struct linkedit_data_command);
  sig->dataoff = layout->code_signature_file_offset;
  sig->datasize = layout->code_signature_file_size;

  header->sizeofcmds = ((guint8 *) (sig + 1)) - ((guint8 *) (header + 1));

  *output_size = sizeof (gum_mach_header_t) + header->sizeofcmds;
}

static void
gum_put_code_signature (gconstpointer header,
                        gconstpointer text,
                        const GumCodeLayout * layout,
                        gpointer output)
{
  GumCsSuperBlob * sb;
  GumCsBlobIndex * bi;
  GumCsDirectory * dir;
  guint8 * ident, * hashes;
  gsize cs_hashes_size, cs_page_size;
  GumCsRequirements * req;
  gsize i;

  cs_hashes_size =
      (layout->code_signature_hash_count * layout->code_signature_hash_size);

  sb = output;
  sb->magic = GUINT32_TO_BE (GUM_CS_MAGIC_EMBEDDED_SIGNATURE);
  sb->length = GUINT32_TO_BE (layout->code_signature_size);
  sb->count = GUINT32_TO_BE (2);

  bi = &sb->index[0];
  bi->type = GUINT32_TO_BE (0);
  bi->offset = GUINT32_TO_BE (28);

  bi = &sb->index[1];
  bi->type = GUINT32_TO_BE (2);
  bi->offset = GUINT32_TO_BE (113 + cs_hashes_size);

  dir = (GumCsDirectory *) (bi + 1);

  ident = ((guint8 *) dir) + 44;
  hashes = ident + 41;

  dir->magic = GUINT32_TO_BE (GUM_CS_MAGIC_CODE_DIRECTORY);
  dir->length = GUINT32_TO_BE (85 + cs_hashes_size);
  dir->version = GUINT32_TO_BE (0x00020001);
  dir->flags = GUINT32_TO_BE (0);
  dir->hash_offset = GUINT32_TO_BE (hashes - (guint8 *) dir);
  dir->ident_offset = GUINT32_TO_BE (ident - (guint8 *) dir);
  dir->num_special_slots = GUINT32_TO_BE (2);
  dir->num_code_slots = GUINT32_TO_BE (layout->code_signature_hash_count);
  dir->code_limit =
      GUINT32_TO_BE (layout->text_file_offset + layout->text_file_size);
  dir->hash_size = layout->code_signature_hash_size;
  dir->hash_type = GUM_CS_HASH_SHA1;
  dir->page_size = log2 (layout->code_signature_page_size);

  req = (GumCsRequirements *) (hashes + cs_hashes_size);
  req->magic = GUINT32_TO_BE (GUM_CS_MAGIC_REQUIREMENTS);
  req->length = GUINT32_TO_BE (12);
  req->count = GUINT32_TO_BE (0);

  CC_SHA1 (req, 12, ident + 1);

  cs_page_size = layout->code_signature_page_size;

  for (i = 0; i != layout->header_file_size / cs_page_size; i++)
  {
    CC_SHA1 (header + (i * cs_page_size), cs_page_size, hashes);
    hashes += 20;
  }

  for (i = 0; i != layout->text_file_size / cs_page_size; i++)
  {
    CC_SHA1 (text + (i * cs_page_size), cs_page_size, hashes);
    hashes += 20;
  }
}
