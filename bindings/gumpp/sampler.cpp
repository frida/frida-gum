#include "gumpp.hpp"

#include "objectwrapper.hpp"

#include <gum/gum-prof.h>

namespace Gum
{
  class SamplerImpl : public ObjectWrapper<SamplerImpl, Sampler, GumSampler>
  {
  public:
    SamplerImpl (GumSampler * handle)
    {
      assign_handle (handle);
    }

    virtual Sample sample () const
    {
      return gum_sampler_sample (handle);
    }
  };

  extern "C" Sampler * BusyCycleSampler_new () { gum_init (); return new SamplerImpl (gum_busy_cycle_sampler_new ()); }
  extern "C" Sampler * CycleSampler_new () { gum_init (); return new SamplerImpl (gum_cycle_sampler_new ()); }
  extern "C" Sampler * MallocCountSampler_new () { gum_init (); return new SamplerImpl (gum_malloc_count_sampler_new ()); }
  extern "C" Sampler * WallClockSampler_new () { gum_init (); return new SamplerImpl (gum_wallclock_sampler_new ()); }

  extern "C" CallCountSampler * CallCountSampler_new (void * first_function, ...)
  {
    gum_init ();

    va_list args;
    va_start (args, first_function);
    GumCallCountSampler * sampler = gum_call_count_sampler_new_valist (first_function, args);
    va_end (args);

    return new CallCountSamplerImpl (sampler);
  }

  extern "C" CallCountSampler * CallCountSampler_new_by_name (char * first_function_name, ...)
  {
    gum_init ();
    return NULL;
  }
}