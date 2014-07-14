#include "gumpp.hpp"

#include "objectwrapper.hpp"
#include "runtime.hpp"

#include <gum/gum.h>

namespace Gum
{
  class BacktracerImpl : public ObjectWrapper<BacktracerImpl, Backtracer, GumBacktracer>
  {
  public:
    BacktracerImpl ()
    {
      Runtime::ref ();
      assign_handle (gum_backtracer_make_default ());
    }

    virtual ~BacktracerImpl ()
    {
      Runtime::unref ();
    }

    virtual void generate (const CpuContext * cpu_context, ReturnAddressArray & return_addresses) const
    {
      gum_backtracer_generate (handle, reinterpret_cast<const GumCpuContext *> (cpu_context), reinterpret_cast<GumReturnAddressArray *> (&return_addresses));
    }
  };

  extern "C" Backtracer * Backtracer_make_default () { return new BacktracerImpl (); }
}