/*
 * Copyright (C) 2021-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdarwingrafter.h"

#include "gumdarwingrafter-priv.h"
#include "gumdarwinmodule-priv.h"
#include "gumleb.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define GUM_BIND_STATE_RESET_SIZE 2

#ifndef GUM_DIET

typedef struct _GumGraftedLayout GumGraftedLayout;
typedef struct _GumGraftedHookTrampoline GumGraftedHookTrampoline;
typedef struct _GumGraftedImportTrampoline GumGraftedImportTrampoline;
typedef struct _GumGraftedRuntime GumGraftedRuntime;
typedef struct _GumCollectFunctionsOperation GumCollectFunctionsOperation;
typedef struct _GumCollectImportsOperation GumCollectImportsOperation;
typedef struct _GumImport GumImport;
typedef struct _GumBindState GumBindState;

enum
{
  PROP_0,
  PROP_PATH,
  PROP_FLAGS,
};

struct _GumDarwinGrafter
{
  GObject parent;

  gchar * path;
  GumDarwinGrafterFlags flags;
  GArray * code_offsets;
};

struct _GumGraftedLayout
{
  gsize page_size;

  GumAddress text_address;

  GumAddress code_address;
  goffset code_offset;
  gsize code_size;

  GumAddress data_address;
  goffset data_offset;
  gsize data_size;

  GumAddress linkedit_address;
  goffset linkedit_offset_in;
  goffset linkedit_offset_out;
  gsize linkedit_size_in;
  gsize linkedit_size_out;
  gsize linkedit_shift;

  goffset rewritten_binds_offset;
  gsize rewritten_binds_capacity;

  goffset rewritten_binds_split_offset;
  gsize rewritten_binds_shift;
};

#pragma pack (push, 1)

struct _GumGraftedHookTrampoline
{
  guint32 on_enter[5];
  guint32 on_leave[3];
  guint32 not_active[1];
  guint32 on_invoke[2];
};

struct _GumGraftedImportTrampoline
{
  guint32 on_enter[3];
  guint32 on_leave[3];
};

struct _GumGraftedRuntime
{
  guint32 do_begin_invocation[2];
  guint32 do_end_invocation[2];
};

#pragma pack (pop)

struct _GumCollectFunctionsOperation
{
  GArray * functions;
  gconstpointer linkedit;
};

struct _GumCollectImportsOperation
{
  GArray * imports;
  GumAddress text_address;
};

struct _GumImport
{
  guint32 slot_offset;
  GumDarwinPageProtection protection;
};

struct _GumBindState
{
  guint segment_index;
  guint64 offset;
  GumDarwinBindType type;
  GumDarwinBindOrdinal library_ordinal;
  gint64 addend;
  guint16 threaded_table_size;
};

static void gum_darwin_grafter_finalize (GObject * object);
static void gum_darwin_grafter_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_grafter_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static gboolean gum_darwin_grafter_compute_layout (GumDarwinGrafter * self,
    GumDarwinModule * module, GumGraftedLayout * layout, GArray ** code_offsets,
    GArray ** imports, GError ** error);
static gboolean gum_collect_functions (
    const GumDarwinFunctionStartsDetails * details, gpointer user_data);
static gboolean gum_collect_import (const GumDarwinBindDetails * details,
    gpointer user_data);
static void gum_normalize_code_offsets (GArray * code_offsets);
static int gum_compare_code_offsets (const void * element_a,
    const void * element_b);
static GByteArray * gum_darwin_grafter_transform_load_commands (
    gconstpointer commands_in, guint32 size_of_commands_in,
    guint32 num_commands_in, const GumGraftedLayout * layout,
    gconstpointer linkedit, guint32 * num_commands_out,
    GByteArray ** merged_binds);
static void gum_darwin_grafter_emit_segments (gpointer output,
    const GumGraftedLayout * layout, GArray * code_offsets, GArray * imports);

static GByteArray * gum_merge_lazy_binds_into_binds (
    const GumDyldInfoCommand * ic, gconstpointer linkedit);
static void gum_replay_bind_state_transitions (const guint8 * start,
    const guint8 * end, GumBindState * state);

G_DEFINE_TYPE (GumDarwinGrafter, gum_darwin_grafter, G_TYPE_OBJECT)

static void
gum_darwin_grafter_class_init (GumDarwinGrafterClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_darwin_grafter_finalize;
  object_class->get_property = gum_darwin_grafter_get_property;
  object_class->set_property = gum_darwin_grafter_set_property;

  g_object_class_install_property (object_class, PROP_PATH,
      g_param_spec_string ("path", "Path", "Path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_FLAGS,
      g_param_spec_flags ("flags", "Flags", "Optional flags",
      GUM_TYPE_DARWIN_GRAFTER_FLAGS, GUM_DARWIN_GRAFTER_FLAGS_NONE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_grafter_init (GumDarwinGrafter * self)
{
  self->code_offsets = g_array_new (FALSE, FALSE, sizeof (guint32));
}

static void
gum_darwin_grafter_finalize (GObject * object)
{
  GumDarwinGrafter * self = GUM_DARWIN_GRAFTER (object);

  g_array_unref (self->code_offsets);
  g_free (self->path);

  G_OBJECT_CLASS (gum_darwin_grafter_parent_class)->finalize (object);
}

static void
gum_darwin_grafter_get_property (GObject * object,
                                 guint property_id,
                                 GValue * value,
                                 GParamSpec * pspec)
{
  GumDarwinGrafter * self = GUM_DARWIN_GRAFTER (object);

  switch (property_id)
  {
    case PROP_PATH:
      g_value_set_string (value, self->path);
      break;
    case PROP_FLAGS:
      g_value_set_flags (value, self->flags);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_grafter_set_property (GObject * object,
                                 guint property_id,
                                 const GValue * value,
                                 GParamSpec * pspec)
{
  GumDarwinGrafter * self = GUM_DARWIN_GRAFTER (object);

  switch (property_id)
  {
    case PROP_PATH:
      g_free (self->path);
      self->path = g_value_dup_string (value);
      break;
    case PROP_FLAGS:
      self->flags = g_value_get_flags (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinGrafter *
gum_darwin_grafter_new_from_file (const gchar * path,
                                  GumDarwinGrafterFlags flags)
{
  return g_object_new (GUM_TYPE_DARWIN_GRAFTER,
      "path", path,
      "flags", flags,
      NULL);
}

void
gum_darwin_grafter_add (GumDarwinGrafter * self,
                        guint32 code_offset)
{
  g_array_append_val (self->code_offsets, code_offset);
}

gboolean
gum_darwin_grafter_graft (GumDarwinGrafter * self,
                          GError ** error)
{
  gboolean success = FALSE;
  GumDarwinModule * module;
  guint i;
  GumGraftedLayout layout;
  GArray * code_offsets = NULL;
  GArray * imports = NULL;
  gconstpointer input;
  GumMachHeader64 mach_header;
  gconstpointer commands_in;
  guint32 size_of_commands_in;
  GByteArray * commands_out = NULL;
  GByteArray * merged_binds = NULL;
  GByteArray * output = NULL;
  gconstpointer end_of_load_commands;
  gsize gap_space_used;
  gconstpointer rest_of_gap;
  FILE * file = NULL;

  module = gum_darwin_module_new_from_file (self->path, GUM_CPU_ARM64,
      GUM_PTRAUTH_INVALID, GUM_DARWIN_MODULE_FLAGS_NONE, error);
  if (module == NULL)
    goto beach;

  for (i = 0; i != module->segments->len; i++)
  {
    const GumDarwinSegment * segment =
        &g_array_index (module->segments, GumDarwinSegment, i);

    if (g_str_has_prefix (segment->name, "__FRIDA_"))
      goto already_grafted;
  }

  if (!gum_darwin_grafter_compute_layout (self, module, &layout, &code_offsets,
      &imports, error))
    goto beach;

  if (code_offsets->len + imports->len == 0)
    goto nothing_to_instrument;

  input = module->image->data;

  /* XXX: for now we assume matching endian */
  memcpy (&mach_header, input, sizeof (GumMachHeader64));

  commands_in = (const GumMachHeader64 *) input + 1;
  size_of_commands_in = mach_header.sizeofcmds;

  commands_out = gum_darwin_grafter_transform_load_commands (commands_in,
      size_of_commands_in, mach_header.ncmds, &layout, input,
      &mach_header.ncmds, &merged_binds);
  mach_header.sizeofcmds = commands_out->len;

  output = g_byte_array_sized_new (
      layout.linkedit_offset_out + layout.linkedit_size_out);

  g_byte_array_append (output, (const guint8 *) &mach_header,
      sizeof (mach_header));

  g_byte_array_append (output, commands_out->data, commands_out->len);

  end_of_load_commands = (const guint8 *) commands_in + size_of_commands_in;
  /* TODO: shift __TEXT if there's not enough space for our load commands */
  gap_space_used = commands_out->len - size_of_commands_in;
  rest_of_gap = (const guint8 *) end_of_load_commands + gap_space_used;
  g_byte_array_append (output, rest_of_gap, layout.linkedit_offset_in -
      ((const guint8 *) rest_of_gap - (const guint8 *) input));

  g_byte_array_set_size (output, output->len + layout.code_size +
      layout.data_size);

  if (layout.rewritten_binds_split_offset == -1)
  {
    g_byte_array_append (output,
        (const guint8 *) input + layout.linkedit_offset_in,
        layout.linkedit_size_in);
  }
  else
  {
    gsize head_size =
        layout.rewritten_binds_split_offset - layout.linkedit_offset_in;

    g_byte_array_append (output,
        (const guint8 *) input + layout.linkedit_offset_in,
        head_size);
    g_byte_array_set_size (output, output->len + layout.rewritten_binds_shift);
    g_byte_array_append (output,
        (const guint8 *) input + layout.rewritten_binds_split_offset,
        layout.linkedit_size_in - head_size);
  }

  if (layout.rewritten_binds_offset != -1)
  {
    guint8 * rewritten_binds_start = output->data +
        layout.rewritten_binds_offset + layout.linkedit_shift;
    memcpy (rewritten_binds_start, merged_binds->data, merged_binds->len);
    if (layout.rewritten_binds_capacity > merged_binds->len)
    {
      memset (rewritten_binds_start + merged_binds->len, 0,
          layout.rewritten_binds_capacity - merged_binds->len);
    }
  }

  gum_darwin_grafter_emit_segments (output->data, &layout, code_offsets,
      imports);

  file = fopen (self->path, "wb");
  if (file == NULL)
    goto io_error;

  if (fwrite (output->data, output->len, 1, file) != 1)
    goto io_error;

  success = TRUE;
  goto beach;

already_grafted:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_EXISTS, "Already grafted");
    goto beach;
  }
nothing_to_instrument:
  {
    success = TRUE;
    goto beach;
  }
io_error:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
        "%s", g_strerror (errno));
  }
beach:
  {
    g_clear_pointer (&file, fclose);
    g_clear_pointer (&output, g_byte_array_unref);
    g_clear_pointer (&merged_binds, g_byte_array_unref);
    g_clear_pointer (&commands_out, g_byte_array_unref);
    g_clear_pointer (&imports, g_array_unref);
    g_clear_pointer (&code_offsets, g_array_unref);
    g_clear_object (&module);

    return success;
  }
}

static gboolean
gum_darwin_grafter_compute_layout (GumDarwinGrafter * self,
                                   GumDarwinModule * module,
                                   GumGraftedLayout * layout,
                                   GArray ** code_offsets,
                                   GArray ** imports,
                                   GError ** error)
{
  gboolean success = FALSE;
  guint i;

  *code_offsets = NULL;
  *imports = NULL;

  memset (layout, 0, sizeof (GumGraftedLayout));
  layout->page_size = 16384;
  layout->linkedit_offset_in = -1;
  for (i = 0; i != module->segments->len; i++)
  {
    const GumDarwinSegment * segment =
        &g_array_index (module->segments, GumDarwinSegment, i);

    if (strcmp (segment->name, "__TEXT") == 0)
    {
      layout->text_address = segment->vm_address;
    }
    else if (strcmp (segment->name, "__LINKEDIT") == 0)
    {
      layout->linkedit_address = segment->vm_address;
      layout->linkedit_offset_in = segment->file_offset;
      layout->linkedit_size_in = segment->file_size;
    }
  }
  if (layout->linkedit_offset_in == -1)
    goto invalid_data;

  layout->linkedit_size_out = layout->linkedit_size_in;
  layout->rewritten_binds_offset = -1;
  layout->rewritten_binds_split_offset = -1;
  if ((self->flags & GUM_DARWIN_GRAFTER_FLAGS_TRANSFORM_LAZY_BINDS) != 0)
  {
    const GumMachHeader64 * mach_header;
    gconstpointer command;

    mach_header = (const GumMachHeader64 *) module->image->data;
    command = mach_header + 1;

    for (i = 0; i != mach_header->ncmds; i++)
    {
      const GumLoadCommand * lc = command;

      if (lc->cmd == GUM_LC_DYLD_INFO_ONLY)
      {
        const GumDyldInfoCommand * ic = command;

        if (ic->lazy_bind_size != 0)
        {
          gboolean lazy_binds_follow_binds;
          gsize addendum;

          lazy_binds_follow_binds =
              ic->lazy_bind_off == ic->bind_off + ic->bind_size;

          layout->rewritten_binds_offset = ic->bind_off;
          layout->rewritten_binds_capacity = GUM_ALIGN_SIZE (ic->bind_size +
              ic->lazy_bind_size + GUM_BIND_STATE_RESET_SIZE, 16);

          if (lazy_binds_follow_binds)
          {
            addendum = GUM_ALIGN_SIZE (layout->rewritten_binds_capacity -
                (ic->bind_size + ic->lazy_bind_size), 16);
            layout->rewritten_binds_capacity =
                ic->bind_size + ic->lazy_bind_size + addendum;
            layout->rewritten_binds_split_offset =
                layout->rewritten_binds_offset + ic->bind_size +
                ic->lazy_bind_size;
          }
          else
          {
            addendum = GUM_ALIGN_SIZE (
                layout->rewritten_binds_capacity - ic->bind_size, 16);
            layout->rewritten_binds_capacity = ic->bind_size + addendum;
            layout->rewritten_binds_split_offset =
                layout->rewritten_binds_offset + ic->bind_size;
          }

          layout->rewritten_binds_shift = addendum;
          layout->linkedit_size_out += addendum;
        }
      }

      command = (const guint8 *) command + lc->cmdsize;
    }
  }

  *code_offsets = g_array_copy (self->code_offsets);
  if ((self->flags & GUM_DARWIN_GRAFTER_FLAGS_INGEST_FUNCTION_STARTS) != 0)
  {
    GumCollectFunctionsOperation op;
    op.functions = *code_offsets;
    op.linkedit = module->image->data;

    gum_darwin_module_enumerate_function_starts (module, gum_collect_functions,
        &op);
  }
  gum_normalize_code_offsets (*code_offsets);

  *imports = g_array_new (FALSE, FALSE, sizeof (GumImport));
  if ((self->flags & GUM_DARWIN_GRAFTER_FLAGS_INGEST_IMPORTS) != 0)
  {
    GumCollectImportsOperation op;
    op.imports = *imports;
    op.text_address = layout->text_address;

    gum_darwin_module_enumerate_binds (module, gum_collect_import, &op);
    gum_darwin_module_enumerate_lazy_binds (module, gum_collect_import, &op);
  }

  layout->code_address = layout->linkedit_address;
  layout->code_offset = layout->linkedit_offset_in;
  layout->code_size = GUM_ALIGN_SIZE (
      (*code_offsets)->len * sizeof (GumGraftedHookTrampoline) +
      (*imports)->len * sizeof (GumGraftedImportTrampoline) +
      sizeof (GumGraftedRuntime),
      layout->page_size);

  layout->data_address = layout->code_address + layout->code_size;
  layout->data_offset = layout->code_offset + layout->code_size;
  layout->data_size = GUM_ALIGN_SIZE (
      sizeof (GumGraftedHeader) +
      (*code_offsets)->len * sizeof (GumGraftedHook) +
      (*imports)->len * sizeof (GumGraftedImport),
      layout->page_size);

  layout->linkedit_offset_out = layout->data_offset + layout->data_size;
  layout->linkedit_shift =
      layout->linkedit_offset_out - layout->linkedit_offset_in;

  success = TRUE;
  goto beach;

invalid_data:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
    goto beach;
  }
beach:
  {
    if (!success)
    {
      g_clear_pointer (imports, g_array_unref);
      g_clear_pointer (code_offsets, g_array_unref);
    }

    return success;
  }
}

static gboolean
gum_collect_functions (const GumDarwinFunctionStartsDetails * details,
                       gpointer user_data)
{
  GumCollectFunctionsOperation * op = user_data;
  const guint8 * p, * end;
  guint32 offset;

  p = (const guint8 *) op->linkedit + details->file_offset;
  end = p + details->size;

  offset = 0;
  while (p != end)
  {
    guint64 delta;

    delta = gum_read_uleb128 (&p, end);
    if (delta == 0)
      break;

    offset += delta;

    g_array_append_val (op->functions, offset);
  }

  return TRUE;
}

static gboolean
gum_collect_import (const GumDarwinBindDetails * details,
                    gpointer user_data)
{
  GumCollectImportsOperation * op = user_data;
  const GumDarwinSegment * segment = details->segment;
  GumImport import;

  import.slot_offset = segment->vm_address - op->text_address + details->offset;
  import.protection = segment->protection;

  g_array_append_val (op->imports, import);

  return TRUE;
}

static void
gum_normalize_code_offsets (GArray * code_offsets)
{
  GHashTable * seen_offsets;
  gint i;

  seen_offsets = g_hash_table_new (NULL, NULL);

  for (i = 0; i < code_offsets->len; i++)
  {
    guint32 offset = g_array_index (code_offsets, guint32, i);

    if (g_hash_table_contains (seen_offsets, GSIZE_TO_POINTER (offset)))
    {
      g_array_remove_index_fast (code_offsets, i);
      i--;
    }
    else
    {
      g_hash_table_add (seen_offsets, GSIZE_TO_POINTER (offset));
    }
  }

  g_hash_table_unref (seen_offsets);

  g_array_sort (code_offsets, gum_compare_code_offsets);
}

static int
gum_compare_code_offsets (const void * element_a,
                          const void * element_b)
{
  const guint32 * a = element_a;
  const guint32 * b = element_b;

  return (gssize) *a - (gssize) *b;
}

static GByteArray *
gum_darwin_grafter_transform_load_commands (gconstpointer commands_in,
                                            guint32 size_of_commands_in,
                                            guint32 num_commands_in,
                                            const GumGraftedLayout * layout,
                                            gconstpointer linkedit,
                                            guint32 * num_commands_out,
                                            GByteArray ** merged_binds)
{
  GByteArray * commands_out;
  guint32 n;
  gconstpointer command_in;
  guint32 i;

  *merged_binds = NULL;

  commands_out = g_byte_array_sized_new (size_of_commands_in);
  n = 0;

  command_in = commands_in;
  for (i = 0; i != num_commands_in; i++)
  {
    const GumLoadCommand * lc = command_in;
    gboolean is_linkedit_command = FALSE;
    guint start_offset;
    gpointer command_out;

    if (lc->cmd == GUM_LC_SEGMENT_64)
    {
      const GumSegmentCommand64 * sc = command_in;

      is_linkedit_command = sc->fileoff == layout->linkedit_offset_in;
    }

    if (is_linkedit_command)
    {
      GumSegmentCommand64 seg;
      GumSection64 sect;

      /* TODO: emit multiple segment pairs when needed */

      seg.cmd = GUM_LC_SEGMENT_64;
      seg.cmdsize = sizeof (seg) + sizeof (sect);
      strcpy (seg.segname, "__FRIDA_TEXT");
      seg.vmaddr = layout->code_address;
      seg.vmsize = layout->code_size;
      seg.fileoff = layout->code_offset;
      seg.filesize = layout->code_size;
      seg.maxprot = GUM_VM_PROT_READ | GUM_VM_PROT_EXECUTE;
      seg.initprot = GUM_VM_PROT_READ | GUM_VM_PROT_EXECUTE;
      seg.nsects = 1;
      seg.flags = 0;
      g_byte_array_append (commands_out, (const guint8 *) &seg, sizeof (seg));

      strcpy (sect.sectname, "__trampolines");
      strcpy (sect.segname, seg.segname);
      sect.addr = seg.vmaddr;
      sect.size = seg.vmsize;
      sect.offset = seg.fileoff;
      sect.align = 2;
      sect.reloff = 0;
      sect.nreloc = 0;
      sect.flags = GUM_S_ATTR_PURE_INSTRUCTIONS | GUM_S_ATTR_SOME_INSTRUCTIONS;
      sect.reserved1 = 0;
      sect.reserved2 = 0;
      sect.reserved3 = 0;
      g_byte_array_append (commands_out, (const guint8 *) &sect, sizeof (sect));

      seg.cmd = GUM_LC_SEGMENT_64;
      seg.cmdsize = sizeof (seg) + sizeof (sect);
      strcpy (seg.segname, "__FRIDA_DATA");
      seg.vmaddr = layout->data_address;
      seg.vmsize = layout->data_size;
      seg.fileoff = layout->data_offset;
      seg.filesize = layout->data_size;
      seg.maxprot = GUM_VM_PROT_READ | GUM_VM_PROT_WRITE;
      seg.initprot = GUM_VM_PROT_READ | GUM_VM_PROT_WRITE;
      seg.nsects = 1;
      seg.flags = 0;
      g_byte_array_append (commands_out, (const guint8 *) &seg, sizeof (seg));

      strcpy (sect.sectname, "__entries");
      strcpy (sect.segname, seg.segname);
      sect.addr = seg.vmaddr;
      sect.size = seg.vmsize;
      sect.offset = seg.fileoff;
      sect.align = 3;
      sect.reloff = 0;
      sect.nreloc = 0;
      sect.flags = 0;
      sect.reserved1 = 0;
      sect.reserved2 = 0;
      sect.reserved3 = 0;
      g_byte_array_append (commands_out, (const guint8 *) &sect, sizeof (sect));

      n += 2;
    }

    start_offset = commands_out->len;
    g_byte_array_append (commands_out, (const guint8 *) lc, lc->cmdsize);
    command_out = commands_out->data + start_offset;
    n++;

#define GUM_SHIFT(field) \
    if (field >= layout->rewritten_binds_split_offset) \
      field += layout->rewritten_binds_shift; \
    field += layout->linkedit_shift

#define GUM_MAYBE_SHIFT(field) \
    if (field != 0 && field >= layout->rewritten_binds_split_offset) \
      field += layout->rewritten_binds_shift; \
    if (field != 0) \
      field += layout->linkedit_shift

    switch (lc->cmd)
    {
      case GUM_LC_SEGMENT_64:
      {
        GumSegmentCommand64 * sc = command_out;

        if (is_linkedit_command)
        {
          guint64 base = sc->vmaddr - sc->fileoff;

          sc->vmsize =
              GUM_ALIGN_SIZE (layout->linkedit_size_out, layout->page_size);

          GUM_SHIFT (sc->fileoff);
          sc->filesize = layout->linkedit_size_out;
          sc->vmaddr = base + sc->fileoff;
        }

        break;
      }
      case GUM_LC_DYLD_INFO_ONLY:
      {
        GumDyldInfoCommand * ic = command_out;

        if (layout->rewritten_binds_offset != -1)
        {
          GByteArray * binds;
          gboolean lazy_binds_follow_binds =
              ic->lazy_bind_off == ic->bind_off + ic->bind_size;

          if (!lazy_binds_follow_binds)
          {
            /*
             * Fill the gap left by merging binds and lazy binds, so that
             * __LINKEDIT has no gaps and codesign is happy. We do this by
             * detecting what is preceding the lazy bindings and extending
             * its size.
             */
            if (ic->rebase_off + ic->rebase_size == ic->lazy_bind_off)
              ic->rebase_size += ic->lazy_bind_size;
            else if (ic->weak_bind_off + ic->weak_bind_size == ic->lazy_bind_off)
              ic->weak_bind_size += ic->lazy_bind_size;
            else if (ic->export_off + ic->export_size == ic->lazy_bind_off)
              ic->export_size += ic->lazy_bind_size;
          }

          /*
           * Get rid of lazy binds so Interceptor can index them. This could
           * also be achieved at runtime by calling dlopen() with RTLD_NOW, but
           * we don't know if the library was loaded RTLD_GLOBAL vs RTLD_LOCAL.
           */
          binds = gum_merge_lazy_binds_into_binds (ic, linkedit);
          *merged_binds = binds;
          ic->bind_off = layout->rewritten_binds_offset + layout->linkedit_shift;

          /*
           * Adjust the size of binds so that everything is contiguous.
           * Not doing so results in a bug in codesign for which the resulting
           * signed binary turns out corrupted.
           */
          ic->bind_size = layout->rewritten_binds_capacity;

          g_assert (binds->len <= ic->bind_size);

          ic->lazy_bind_off = 0;
          ic->lazy_bind_size = 0;
        }
        else
        {
          GUM_MAYBE_SHIFT (ic->bind_off);
          GUM_MAYBE_SHIFT (ic->lazy_bind_off);
        }

        GUM_MAYBE_SHIFT (ic->rebase_off);
        GUM_MAYBE_SHIFT (ic->weak_bind_off);
        GUM_MAYBE_SHIFT (ic->export_off);

        break;
      }
      case GUM_LC_SYMTAB:
      {
        GumSymtabCommand * sc = command_out;

        GUM_SHIFT (sc->symoff);
        GUM_SHIFT (sc->stroff);

        break;
      }
      case GUM_LC_DYSYMTAB:
      {
        GumDysymtabCommand * dc = command_out;

        GUM_MAYBE_SHIFT (dc->tocoff);
        GUM_MAYBE_SHIFT (dc->modtaboff);
        GUM_MAYBE_SHIFT (dc->extrefsymoff);
        GUM_SHIFT (dc->indirectsymoff); /* XXX: is it always specified? */
        GUM_MAYBE_SHIFT (dc->extreloff);
        GUM_MAYBE_SHIFT (dc->locreloff);

        break;
      }
      case GUM_LC_CODE_SIGNATURE:
      case GUM_LC_SEGMENT_SPLIT_INFO:
      case GUM_LC_FUNCTION_STARTS:
      case GUM_LC_DATA_IN_CODE:
      case GUM_LC_DYLIB_CODE_SIGN_DRS:
      case GUM_LC_LINKER_OPTIMIZATION_HINT:
      {
        GumLinkeditDataCommand * dc = command_out;

        GUM_SHIFT (dc->dataoff);

        break;
      }
      default:
        break;
    }

    command_in = (const guint8 *) command_in + lc->cmdsize;
  }

  *num_commands_out = n;

  return commands_out;
}

static void
gum_darwin_grafter_emit_segments (gpointer output,
                                  const GumGraftedLayout * layout,
                                  GArray * code_offsets,
                                  GArray * imports)
{
  gpointer code, data;
  GumGraftedHookTrampoline * hook_trampolines;
  GumGraftedImportTrampoline * import_trampolines;
  GumGraftedHeader * header;
  GumGraftedHook * hook_entries;
  GumGraftedImport * import_entries;
  GumAddress hook_trampolines_addr, import_trampolines_addr;
  GumAddress runtime_addr, do_begin_invocation_addr, do_end_invocation_addr;
  GumAddress header_addr, begin_invocation_addr, end_invocation_addr;
  GumAddress hook_entries_addr, import_entries_addr;
  GumArm64Writer cw;
  guint i;

  code = (guint8 *) output + layout->code_offset;
  data = (guint8 *) output + layout->data_offset;

  memset (code, 0, layout->code_size);
  memset (data, 0, layout->data_size);

  hook_trampolines = code;
  import_trampolines =
      (GumGraftedImportTrampoline *) (hook_trampolines + code_offsets->len);
  header = data;
  hook_entries = (GumGraftedHook *) (header + 1);
  import_entries = (GumGraftedImport *) (hook_entries + code_offsets->len);

  header->abi_version = GUM_DARWIN_GRAFTER_ABI_VERSION;
  header->num_hooks = code_offsets->len;
  header->num_imports = imports->len;

  hook_trampolines_addr = layout->code_address;
  import_trampolines_addr = hook_trampolines_addr +
      code_offsets->len * sizeof (GumGraftedHookTrampoline);
  runtime_addr = import_trampolines_addr +
      imports->len * sizeof (GumGraftedImportTrampoline);
  do_begin_invocation_addr = runtime_addr +
      G_STRUCT_OFFSET (GumGraftedRuntime, do_begin_invocation);
  do_end_invocation_addr = runtime_addr +
      G_STRUCT_OFFSET (GumGraftedRuntime, do_end_invocation);

  header_addr = layout->data_address;
  begin_invocation_addr = header_addr +
      G_STRUCT_OFFSET (GumGraftedHeader, begin_invocation);
  end_invocation_addr = header_addr +
      G_STRUCT_OFFSET (GumGraftedHeader, end_invocation);

  hook_entries_addr = header_addr + sizeof (GumGraftedHeader);
  import_entries_addr =
      hook_entries_addr + code_offsets->len * sizeof (GumGraftedHook);

  gum_arm64_writer_init (&cw, NULL);

  for (i = 0; i != code_offsets->len; i++)
  {
    guint32 code_offset, * code_instructions, overwritten_insn;
    GumAddress code_addr;
    GumGraftedHookTrampoline * trampoline = &hook_trampolines[i];
    GumAddress trampoline_addr, on_enter_addr;
    GumGraftedHook * entry = &hook_entries[i];
    GumAddress entry_addr, flags_addr, user_data_addr;
    gconstpointer not_active = trampoline;

    code_offset = g_array_index (code_offsets, guint32, i);
    code_addr = layout->text_address + code_offset;
    code_instructions = (guint32 *) ((guint8 *) output + code_offset);

    overwritten_insn = code_instructions[0];

    trampoline_addr =
        hook_trampolines_addr + i * sizeof (GumGraftedHookTrampoline);
    on_enter_addr = trampoline_addr +
        G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_enter);

    entry_addr = hook_entries_addr + i * sizeof (GumGraftedHook);
    flags_addr = entry_addr + G_STRUCT_OFFSET (GumGraftedHook, flags);
    user_data_addr = entry_addr + G_STRUCT_OFFSET (GumGraftedHook, user_data);

    gum_arm64_writer_reset (&cw, code_instructions);
    cw.pc = code_addr;
    gum_arm64_writer_put_b_imm (&cw, on_enter_addr);
    gum_arm64_writer_flush (&cw);

    gum_arm64_writer_reset (&cw, trampoline->on_enter);
    cw.pc = on_enter_addr;
    gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_ldr_reg_u32_ptr (&cw, ARM64_REG_W16, flags_addr);
    gum_arm64_writer_put_tbz_reg_imm_label (&cw, ARM64_REG_W16, 0, not_active);
    gum_arm64_writer_put_ldr_reg_u64_ptr (&cw, ARM64_REG_X17, user_data_addr);
    gum_arm64_writer_put_b_imm (&cw, do_begin_invocation_addr);

    g_assert (cw.pc == trampoline_addr +
        G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_leave));
    gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_ldr_reg_u64_ptr (&cw, ARM64_REG_X17, user_data_addr);
    gum_arm64_writer_put_b_imm (&cw, do_end_invocation_addr);

    g_assert (cw.pc == trampoline_addr +
        G_STRUCT_OFFSET (GumGraftedHookTrampoline, not_active));
    gum_arm64_writer_put_label (&cw, not_active);
    gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X16, ARM64_REG_X17);

    g_assert (cw.pc == trampoline_addr +
        G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_invoke));
    /* TODO: use Arm64Relocator */
    gum_arm64_writer_put_instruction (&cw, overwritten_insn);
    gum_arm64_writer_put_b_imm (&cw, code_addr + sizeof (overwritten_insn));

    gum_arm64_writer_flush (&cw);
    g_assert (
        gum_arm64_writer_offset (&cw) == sizeof (GumGraftedHookTrampoline));

    entry->code_offset = code_offset;
    entry->trampoline_offset = trampoline_addr - layout->text_address;
    entry->flags =
        sizeof (GumGraftedHookTrampoline)                     << 24 |
        G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_enter)  << 17 |
        G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_leave)  << 10 |
        G_STRUCT_OFFSET (GumGraftedHookTrampoline, on_invoke) <<  3 |
        0x0;
  }

  for (i = 0; i != imports->len; i++)
  {
    const GumImport * import;
    GumGraftedImportTrampoline * trampoline = &import_trampolines[i];
    GumAddress trampoline_addr;
    GumGraftedImport * entry = &import_entries[i];
    GumAddress entry_addr, user_data_addr;

    import = &g_array_index (imports, GumImport, i);

    trampoline_addr =
        import_trampolines_addr + i * sizeof (GumGraftedImportTrampoline);

    entry_addr = import_entries_addr + i * sizeof (GumGraftedImport);
    user_data_addr = entry_addr + G_STRUCT_OFFSET (GumGraftedImport, user_data);

    gum_arm64_writer_reset (&cw, trampoline->on_enter);
    cw.pc = trampoline_addr +
        G_STRUCT_OFFSET (GumGraftedImportTrampoline, on_enter);
    gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_ldr_reg_u64_ptr (&cw, ARM64_REG_X17, user_data_addr);
    gum_arm64_writer_put_b_imm (&cw, do_begin_invocation_addr);

    g_assert (cw.pc == trampoline_addr +
        G_STRUCT_OFFSET (GumGraftedImportTrampoline, on_leave));
    gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X16, ARM64_REG_X17);
    gum_arm64_writer_put_ldr_reg_u64_ptr (&cw, ARM64_REG_X17, user_data_addr);
    gum_arm64_writer_put_b_imm (&cw, do_end_invocation_addr);

    gum_arm64_writer_flush (&cw);
    g_assert (
        gum_arm64_writer_offset (&cw) == sizeof (GumGraftedImportTrampoline));

    entry->slot_offset = import->slot_offset;
    entry->trampoline_offset = trampoline_addr - layout->text_address;
    entry->flags =
        sizeof (GumGraftedImportTrampoline)                     << 24 |
        G_STRUCT_OFFSET (GumGraftedImportTrampoline, on_enter)  << 17 |
        G_STRUCT_OFFSET (GumGraftedImportTrampoline, on_leave)  << 10 |
        0x0;
  }

  gum_arm64_writer_reset (&cw, import_trampolines + imports->len);

  cw.pc = do_begin_invocation_addr;
  gum_arm64_writer_put_ldr_reg_u64_ptr (&cw, ARM64_REG_X16,
      begin_invocation_addr);
  gum_arm64_writer_put_br_reg (&cw, ARM64_REG_X16);

  g_assert (cw.pc == do_end_invocation_addr);
  gum_arm64_writer_put_ldr_reg_u64_ptr (&cw, ARM64_REG_X16,
      end_invocation_addr);
  gum_arm64_writer_put_br_reg (&cw, ARM64_REG_X16);

  gum_arm64_writer_clear (&cw);
}

static GByteArray *
gum_merge_lazy_binds_into_binds (const GumDyldInfoCommand * ic,
                                 gconstpointer linkedit)
{
  GByteArray * binds;
  guint8 terminator;

  binds = g_byte_array_sized_new (ic->bind_size + ic->lazy_bind_size);

  g_byte_array_append (binds, (const guint8 *) linkedit + ic->bind_off,
      ic->bind_size);

  while (binds->len > 0 && (binds->data[binds->len - 1] & GUM_BIND_OPCODE_MASK)
      == GUM_BIND_OPCODE_DONE)
  {
    g_byte_array_set_size (binds, binds->len - 1);
  }

  if (ic->lazy_bind_size != 0)
  {
    GumBindState state;
    const guint8 * start, * end, * p;
    const gsize pointer_size = sizeof (guint64);

    gum_replay_bind_state_transitions (binds->data, binds->data + binds->len,
        &state);

    start = (const guint8 *) linkedit + ic->lazy_bind_off;
    end = start + ic->lazy_bind_size;
    p = start;

    if (state.addend != 0)
    {
      guint8 reset_state[GUM_BIND_STATE_RESET_SIZE] = {
        GUM_BIND_OPCODE_SET_ADDEND_SLEB,
        0
      };

      /*
       * Prevent some of the previous state from bleeding into the converted
       * lazy bindings, which state must be treated as a different "context".
       */
      g_byte_array_append (binds, reset_state, sizeof (reset_state));

      state.addend = 0;
    }

    while (p != end)
    {
      const guint8 * opcode_start;
      guint8 opcode, immediate;
      gboolean keep;
      GumDarwinBindOrdinal new_library_ordinal;
      gint64 new_addend;
      guint new_segment_index;
      guint64 new_offset;

      opcode_start = p;

      opcode = *p & GUM_BIND_OPCODE_MASK;
      immediate = *p & GUM_BIND_IMMEDIATE_MASK;
      p++;

      keep = FALSE;
      switch (opcode)
      {
        case GUM_BIND_OPCODE_DONE:
          break;
        case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
          switch (opcode)
          {
            case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
              new_library_ordinal = immediate;
              break;
            case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
              new_library_ordinal = gum_read_uleb128 (&p, end);
              break;
            case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
              if (immediate == 0)
              {
                new_library_ordinal = 0;
              }
              else
              {
                gint8 value = GUM_BIND_OPCODE_MASK | immediate;
                new_library_ordinal = value;
              }
              break;
            default:
              g_assert_not_reached ();
          }

          if (new_library_ordinal != state.library_ordinal)
          {
            state.library_ordinal = new_library_ordinal;
            keep = TRUE;
          }

          break;
        case GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
          while (*p != '\0')
            p++;
          p++;
          keep = TRUE;
          break;
        case GUM_BIND_OPCODE_SET_TYPE_IMM:
          if (immediate != state.type)
          {
            state.type = immediate;
            keep = TRUE;
          }
          break;
        case GUM_BIND_OPCODE_SET_ADDEND_SLEB:
          new_addend = gum_read_sleb128 (&p, end);
          if (new_addend != state.addend)
          {
            state.addend = new_addend;
            keep = TRUE;
          }
          break;
        case GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
          new_segment_index = immediate;
          new_offset = gum_read_uleb128 (&p, end);
          if (new_segment_index != state.segment_index ||
              new_offset != state.offset)
          {
            state.segment_index = new_segment_index;
            state.offset = new_offset;
            keep = TRUE;
          }
          break;
        case GUM_BIND_OPCODE_ADD_ADDR_ULEB:
          new_offset = state.offset + gum_read_uleb128 (&p, end);
          if (new_offset != state.offset)
          {
            state.offset = new_offset;
            keep = TRUE;
          }
          break;
        case GUM_BIND_OPCODE_DO_BIND:
          state.offset += pointer_size;
          keep = TRUE;
          break;
        case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        case GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        default:
          goto malformed_lazy_bind;
      }

      if (keep)
        g_byte_array_append (binds, opcode_start, p - opcode_start);
    }
  }

malformed_lazy_bind:
  terminator = GUM_BIND_OPCODE_DONE;
  g_byte_array_append (binds, &terminator, sizeof (terminator));

  return binds;
}

static void
gum_replay_bind_state_transitions (const guint8 * start,
                                   const guint8 * end,
                                   GumBindState * state)
{
  const gsize pointer_size = sizeof (guint64);
  const guint8 * p;
  gboolean done;

  p = start;
  done = FALSE;

  state->segment_index = 0;
  state->offset = 0;
  state->type = 0;
  state->library_ordinal = 0;
  state->addend = 0;
  state->threaded_table_size = 0;

  while (!done && p != end)
  {
    guint8 opcode = *p & GUM_BIND_OPCODE_MASK;
    guint8 immediate = *p & GUM_BIND_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case GUM_BIND_OPCODE_DONE:
        done = TRUE;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        state->library_ordinal = immediate;
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        state->library_ordinal = gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        if (immediate == 0)
        {
          state->library_ordinal = 0;
        }
        else
        {
          gint8 value = GUM_BIND_OPCODE_MASK | immediate;
          state->library_ordinal = value;
        }
        break;
      case GUM_BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        while (*p != '\0')
          p++;
        p++;
        break;
      case GUM_BIND_OPCODE_SET_TYPE_IMM:
        state->type = immediate;
        break;
      case GUM_BIND_OPCODE_SET_ADDEND_SLEB:
        state->addend = gum_read_sleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        state->segment_index = immediate;
        state->offset = gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_ADD_ADDR_ULEB:
        state->offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND:
        state->offset += pointer_size;
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        state->offset += pointer_size + gum_read_uleb128 (&p, end);
        break;
      case GUM_BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        state->offset += pointer_size + (immediate * pointer_size);
        break;
      case GUM_BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
      {
        guint64 count, skip;

        count = gum_read_uleb128 (&p, end);
        skip = gum_read_uleb128 (&p, end);
        state->offset += count * (pointer_size + skip);

        break;
      }
      case GUM_BIND_OPCODE_THREADED:
      {
        switch (immediate)
        {
          case GUM_BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
            state->type = GUM_DARWIN_BIND_THREADED_TABLE;
            state->threaded_table_size = gum_read_uleb128 (&p, end);
            break;
          case GUM_BIND_SUBOPCODE_THREADED_APPLY:
            state->type = GUM_DARWIN_BIND_THREADED_ITEMS;
            break;
          default:
            return;
        }

        break;
      }
      default:
        return;
    }
  }
}

#endif

void
_gum_grafted_hook_activate (GumGraftedHook * self)
{
  self->flags |= 1;
}

void
_gum_grafted_hook_deactivate (GumGraftedHook * self)
{
  self->flags &= ~1;
}
