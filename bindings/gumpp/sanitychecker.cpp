#include "gumpp.hpp"

#include "podwrapper.hpp"

#include <gum/gum-heap.h>
#include <iostream>

namespace Gum
{
  class SanityCheckerImpl : public PodWrapper<SanityCheckerImpl, SanityChecker, GumSanityChecker>
  {
  public:
    explicit SanityCheckerImpl (const HeapApi * heap_api)
    {
      GumHeapApiList * heap_apis = gum_heap_api_list_new ();
      gum_heap_api_list_add (heap_apis, reinterpret_cast<const GumHeapApi *> (heap_api));
      assign_handle (gum_sanity_checker_new_with_heap_apis (heap_apis, output_to_stderr, NULL));
      gum_heap_api_list_free (heap_apis);
    }

    ~SanityCheckerImpl ()
    {
      gum_sanity_checker_destroy (handle);
    }

    virtual void enable_backtraces_for_blocks_of_size (int size)
    {
      gum_sanity_checker_enable_backtraces_for_blocks_of_size (handle, size);
    }

    virtual void set_front_alignment_granularity (unsigned int granularity)
    {
      gum_sanity_checker_set_front_alignment_granularity (handle, granularity);
    }

    virtual void begin (unsigned int flags)
    {
      gum_sanity_checker_begin (handle, flags);
    }

    virtual bool end ()
    {
      return gum_sanity_checker_end (handle) != FALSE;
    }

  protected:
    static void output_to_stderr (const gchar * text, gpointer user_data)
    {
      (void) user_data;

      std::cerr << text;
    }
  };

  extern "C" SanityChecker * SanityChecker_new (void) { gum_init (); return new SanityCheckerImpl (0); }
  extern "C" SanityChecker * SanityChecker_new_with_heap_api (const HeapApi * api)  { gum_init (); return new SanityCheckerImpl (api); }
}