/*
 * Copyright (C) 2009-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "tracer-fixture.c"

TEST_LIST_BEGIN (tracer)
  TRACER_TESTENTRY (tid_and_name)
  TRACER_TESTENTRY (level_and_timestamp)
  TRACER_TESTENTRY (enter_leave)
  TRACER_TESTENTRY (minimal_size)
  TRACER_TESTENTRY (relocation)
  TRACER_TESTENTRY (follow_redirects)
  TRACER_TESTENTRY (already_added)
  TRACER_TESTENTRY (one_argument)
  TRACER_TESTENTRY (many_arguments)

  TRACER_TESTENTRY (torture)

  TEST_ENTRY_SIMPLE ("Core/Tracer", test, ringbuffer)
TEST_LIST_END ()

#define TORTURE_ENTRY_COUNT 200000

static gpointer torture_writer_thread (gpointer data);

static gpointer ringbuffer_reader (gpointer data);
static gpointer ringbuffer_writer (gpointer data);

static void target_function_alpha (GString * s);
static void target_function_beta (GString * s);
static void target_function_gamma (GString * s);
static int target_function_argh (int a, int b, int c, int d, int e, int f,
    int g, int h, int i, int j, int k);

TRACER_TESTCASE (tid_and_name)
{
  GumTraceEntry * entries;
  guint num_entries;

  target_function_alpha (NULL);
  target_function_beta (NULL);

  gum_tracer_add_function (fixture->tracer, "alpha", target_function_alpha);
  gum_tracer_add_function (fixture->tracer, "beta", target_function_beta);

  g_assert (gum_tracer_drain (fixture->tracer, &num_entries) == NULL);
  g_assert_cmpuint (num_entries, ==, 0);

  target_function_alpha (NULL);
  target_function_beta (NULL);
  target_function_alpha (NULL);

  entries = gum_tracer_drain (fixture->tracer, &num_entries);
  g_assert (entries != NULL);

  g_assert_cmpuint (num_entries, ==, 6);

  gum_assert_cmp_name_of (&entries[0], ==, "alpha");
  gum_assert_cmp_name_of (&entries[1], ==, "alpha");
  gum_assert_cmp_name_of (&entries[2], ==, "beta");
  gum_assert_cmp_name_of (&entries[3], ==, "beta");
  gum_assert_cmp_name_of (&entries[4], ==, "alpha");
  gum_assert_cmp_name_of (&entries[5], ==, "alpha");

  gum_assert_cmp_thread_id_of (&entries[0], !=, 0);
  gum_assert_cmp_thread_ids_of (&entries[1], ==, &entries[0]);
  gum_assert_cmp_thread_ids_of (&entries[2], ==, &entries[0]);
  gum_assert_cmp_thread_ids_of (&entries[3], ==, &entries[0]);
  gum_assert_cmp_thread_ids_of (&entries[4], ==, &entries[0]);
  gum_assert_cmp_thread_ids_of (&entries[5], ==, &entries[0]);

  gum_assert_cmp_arglist_size_of (&entries[0], ==, 0);
  gum_assert_cmp_arglist_size_of (&entries[1], ==, 0);
  gum_assert_cmp_arglist_size_of (&entries[2], ==, 0);
  gum_assert_cmp_arglist_size_of (&entries[3], ==, 0);
  gum_assert_cmp_arglist_size_of (&entries[4], ==, 0);
  gum_assert_cmp_arglist_size_of (&entries[5], ==, 0);

  g_free (entries);
}

TRACER_TESTCASE (level_and_timestamp)
{
  GumTraceEntry * entries;
  guint num_entries;

  gum_tracer_add_function (fixture->tracer, "gamma", target_function_gamma);
  gum_tracer_add_function (fixture->tracer, "alpha", target_function_alpha);

  target_function_gamma (NULL);

  entries = gum_tracer_drain (fixture->tracer, &num_entries);
  g_assert (entries != NULL);

  g_assert_cmpuint (num_entries, ==, 4);

  gum_assert_cmp_name_of (&entries[0], ==, "gamma");
  gum_assert_cmp_name_of (&entries[1], ==, "alpha");
  gum_assert_cmp_name_of (&entries[2], ==, "alpha");
  gum_assert_cmp_name_of (&entries[3], ==, "gamma");

  gum_assert_cmp_depth_of (&entries[0], ==, 0);
  gum_assert_cmp_depth_of (&entries[1], ==, 1);
  gum_assert_cmp_depth_of (&entries[2], ==, 1);
  gum_assert_cmp_depth_of (&entries[3], ==, 0);

  gum_assert_cmp_timestamp_of (&entries[0], !=, 0);
  gum_assert_cmp_timestamps_of (&entries[1], >, &entries[0]);
  gum_assert_cmp_timestamps_of (&entries[2], >=, &entries[1]);
  gum_assert_cmp_timestamps_of (&entries[3], >, &entries[0]);

  g_free (entries);
}

TRACER_TESTCASE (enter_leave)
{
  GumTraceEntry * entries;
  guint num_entries;

  gum_tracer_add_function (fixture->tracer, "alpha", target_function_alpha);
  gum_tracer_add_function (fixture->tracer, "beta", target_function_beta);

  target_function_alpha (NULL);
  target_function_beta (NULL);

  entries = gum_tracer_drain (fixture->tracer, &num_entries);
  g_assert (entries != NULL);

  g_assert_cmpuint (num_entries, ==, 4);

  gum_assert_cmp_type_of (&entries[0], ==, GUM_ENTRY_ENTER);
  gum_assert_cmp_type_of (&entries[1], ==, GUM_ENTRY_LEAVE);
  gum_assert_cmp_type_of (&entries[2], ==, GUM_ENTRY_ENTER);
  gum_assert_cmp_type_of (&entries[3], ==, GUM_ENTRY_LEAVE);

  g_free (entries);
}

TRACER_TESTCASE (minimal_size)
{
  guint8 tpl_code[] = {
    0x33, 0xc0,       /* xor eax, eax */
    0xc2, 0x08, 0x00  /* retn 8 */
  };
  guint8 * code;

  code = test_tracer_fixture_dup_code (fixture, tpl_code, sizeof (tpl_code));
  g_assert (gum_tracer_add_function (fixture->tracer, "foo", code) == TRUE);
}

TRACER_TESTCASE (relocation)
{
  const guint8 tpl_code[] = {
    0x55,                         /* push ebp     */
    0x8b, 0xec,                   /* mov ebp, esp */
    0xe8, 0x04, 0x00, 0x00, 0x00, /* call dummy   */
    0x8b, 0xe5,                   /* mov esp, ebp */
    0x5d,                         /* pop ebp      */
    0xc3,                         /* retn         */

/* dummy:                                         */
    0xc3                          /* retn         */
  };
  guint8 * code;
  GCallback func;
  GumTraceEntry * entries;
  guint num_entries;

  code = test_tracer_fixture_dup_code (fixture, tpl_code, sizeof (tpl_code));
  func = G_CALLBACK (code);

  g_assert (gum_tracer_add_function (fixture->tracer, "foo", code) == TRUE);

  func ();

  entries = gum_tracer_drain (fixture->tracer, &num_entries);
  g_assert (entries != NULL);

  g_assert_cmpuint (num_entries, ==, 2);

  g_free (entries);
}

TRACER_TESTCASE (follow_redirects)
{
  const guint8 tpl_code[] = {
    0xe9, 0x01, 0x00, 0x00, 0x00, /* jmp proxy */
    0xcc,
  /* proxy: */
    0xe9, 0x02, 0x00, 0x00, 0x00, /* jmp impl */
    0xcc,
    0xcc,
  /* impl: */
    0x55,                         /* push ebp     */
    0x8b, 0xec,                   /* mov ebp, esp */
    0x8b, 0xe5,                   /* mov esp, ebp */
    0x5d,                         /* pop ebp      */
    0xc3,                         /* retn         */
  };
  guint8 * code;
  const guint code_impl_offset = 13;
  GCallback func;
  GumTraceEntry * entries;
  guint num_entries;

  code = test_tracer_fixture_dup_code (fixture, tpl_code, sizeof (tpl_code));

  g_assert (gum_tracer_add_function (fixture->tracer, "foo", code) == TRUE);

  func = G_CALLBACK (code + code_impl_offset);
  func ();

  entries = gum_tracer_drain (fixture->tracer, &num_entries);
  g_assert (entries != NULL);

  g_assert_cmpuint (num_entries, ==, 2);

  g_free (entries);
}

TRACER_TESTCASE (already_added)
{
  g_assert (gum_tracer_add_function (fixture->tracer,
      "alpha", target_function_alpha) == TRUE);
  g_assert (gum_tracer_add_function (fixture->tracer,
      "alpha", target_function_alpha) == FALSE);
}

TRACER_TESTCASE (one_argument)
{
  GumFunctionDetails details;
  GString * s;
  GumTraceEntry * entries;
  guint num_entries;

  details.name = "alpha";
  details.address = target_function_alpha;
  details.num_arguments = 1;

  gum_tracer_add_function_with (fixture->tracer, &details);

  g_assert (gum_tracer_drain (fixture->tracer, &num_entries) == NULL);
  g_assert_cmpuint (num_entries, ==, 0);

  s = g_string_new ("");
  target_function_alpha (s);
  g_string_free (s, TRUE);

  entries = gum_tracer_drain (fixture->tracer, &num_entries);

  g_assert_cmpuint (num_entries, ==, 3);

  gum_assert_cmp_arglist_size_of (&entries[0], ==, sizeof (gpointer));
  g_assert (*((GString **) GUM_TRACE_ENTRY_DATA (&entries[1])) == s);
  gum_assert_cmp_arglist_size_of (&entries[2], ==, 0);

  g_free (entries);
}

TRACER_TESTCASE (many_arguments)
{
  GumFunctionDetails details;
  GumTraceEntry * entries;
  guint num_entries, expected_count;

  details.name = "argh";
  details.address = target_function_argh;
  details.num_arguments = 11;

  gum_tracer_add_function_with (fixture->tracer, &details);

  g_assert (gum_tracer_drain (fixture->tracer, &num_entries) == NULL);
  g_assert_cmpuint (num_entries, ==, 0);

  target_function_argh (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31);

  entries = gum_tracer_drain (fixture->tracer, &num_entries);

  g_assert_cmpuint (num_entries, >=, 3);
  gum_assert_cmp_arglist_size_of (&entries[0], ==, 11 * sizeof (gpointer));

  expected_count = 1; /* ENTER */
  expected_count +=
      GUM_TRACE_ENTRY_ARGLIST_SIZE (&entries[0]) / sizeof (GumTraceEntry);
  if (GUM_TRACE_ENTRY_ARGLIST_SIZE (&entries[0]) % sizeof (GumTraceEntry) != 0)
    expected_count++;
  expected_count++; /* LEAVE */
  g_assert_cmpuint (num_entries, ==, expected_count);

  gum_assert_cmp_arglist_size_of (&entries[num_entries - 1], ==, 0);

  g_free (entries);
}

TRACER_TESTCASE (torture)
{
  GThread * th;
  GumTraceEntry * entries;
  guint num_entries;
  guint total_count = 0;

  gum_tracer_add_function (fixture->tracer, "alpha", target_function_alpha);

  th = g_thread_create (torture_writer_thread, NULL, TRUE, NULL);

  g_usleep (G_USEC_PER_SEC);

  do
  {
    guint i;

    entries = gum_tracer_drain (fixture->tracer, &num_entries);

    for (i = 0; i < num_entries; i++)
    {
      const gchar * name = gum_tracer_name_id_to_string (fixture->tracer,
          GUM_TRACE_ENTRY_NAME_ID (&entries[i]));
      g_assert (name != NULL);
    }

    g_free (entries);

    total_count += num_entries;
  }
  while (total_count < TORTURE_ENTRY_COUNT);

  g_thread_join (th);
}

static gpointer
torture_writer_thread (gpointer data)
{
  guint i;

  for (i = 0; i < TORTURE_ENTRY_COUNT / 2; i++)
  {
    target_function_alpha (NULL);
  }

  return NULL;
}

typedef struct _RingItem RingItem;
typedef struct _RingBuffer RingBuffer;

struct _RingItem
{
  gboolean initialized;
  gchar value;
};

struct _RingBuffer
{
  RingItem items[1];

  volatile gint readpos;
  volatile gint writepos;
};

typedef struct _RingWriterContext RingWriterContext;

struct _RingWriterContext
{
  RingBuffer * rb;
  gchar base;
};

static void
test_ringbuffer (void)
{
  RingBuffer rb;
  RingWriterContext writer_ctx_a, writer_ctx_b;
  GThread * reader, * writer_a, * writer_b;

  memset (rb.items, 0, sizeof (rb.items));
  rb.readpos = 0;
  rb.writepos = 0;

  writer_ctx_a.rb = &rb;
  writer_ctx_a.base = 'A';
  writer_ctx_b.rb = &rb;
  writer_ctx_b.base = 'a';

  reader = g_thread_create (ringbuffer_reader, &rb, TRUE, NULL);
  writer_a = g_thread_create (ringbuffer_writer, &writer_ctx_a, TRUE, NULL);
  writer_b = g_thread_create (ringbuffer_writer, &writer_ctx_b, TRUE, NULL);

  g_thread_join (reader);
  g_thread_join (writer_a);
  g_thread_join (writer_b);
}

#define RING_BUFFER_SIZE(r) (G_N_ELEMENTS ((r)->items))

static gboolean
ring_buffer_read (RingBuffer * rb,
                  gchar * value)
{
  RingItem * item;
  gint available;

  available = (rb->writepos - rb->readpos);
  if (available == 0)
    return FALSE;

  item = &rb->items[rb->readpos % RING_BUFFER_SIZE (rb)];
  while (!item->initialized)
    g_thread_yield ();
  *value = item->value;
  item->initialized = FALSE;
  rb->readpos++;
  return TRUE;
}

static void
ring_buffer_write (RingBuffer * rb,
                   gchar value)
{
  RingItem * item;
  gint pos;

  pos = g_atomic_int_exchange_and_add (&rb->writepos, 1);
  while (pos - rb->readpos >= RING_BUFFER_SIZE (rb))
    g_thread_yield ();
  item = &rb->items[pos % RING_BUFFER_SIZE (rb)];
  item->value = value;
  item->initialized = TRUE;
}

static gpointer
ringbuffer_reader (gpointer data)
{
  RingBuffer * rb = data;
  guint i;

  for (i = 0; i < 20; i++)
  {
    gchar value;

    while (!ring_buffer_read (rb, &value))
      g_usleep (G_USEC_PER_SEC / 100);

    /*g_print ("reader: %c\n", value);*/
  }

  return NULL;
}

static gpointer
ringbuffer_writer (gpointer data)
{
  RingWriterContext * ctx = data;
  guint i;

  for (i = 0; i < 10; i++)
  {
    ring_buffer_write (ctx->rb, ctx->base + i);
  }

  return NULL;
}

static void GUM_NOINLINE
target_function_alpha (GString * s)
{
  guint i;

  if (s != NULL)
  {
    g_string_append (s, G_STRFUNC);
    g_string_append_c (s, '[');
    for (i = 0; i < 3; i++)
      g_string_append_c (s, 'a' + i);
    g_string_append_c (s, ']');
  }
  else
  {
    fflush (stdout);
  }
}

static void GUM_NOINLINE
target_function_beta (GString * s)
{
  guint i;

  if (s != NULL)
  {
    g_string_append (s, G_STRFUNC);
    g_string_append_c (s, '[');
    for (i = 0; i < 3; i++)
      g_string_append_c (s, 'A' + i);
    g_string_append_c (s, ']');
  }
  else
  {
    fflush (stdout);
  }
}

static void GUM_NOINLINE
target_function_gamma (GString * s)
{
  g_usleep (G_USEC_PER_SEC / 10 / 3);
  target_function_alpha (s);
}

static int GUM_NOINLINE
target_function_argh (int a,
                      int b,
                      int c,
                      int d,
                      int e,
                      int f,
                      int g,
                      int h,
                      int i,
                      int j,
                      int k)
{
  fflush (stdout);
  return a + b + c + d + e + f + g + h + i + j + k;
}
