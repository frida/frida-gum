#ifndef __GUMPP_HPP__
#define __GUMPP_HPP__

#if !defined (GUMPP_STATIC) && defined (WIN32)
#  ifdef GUMPP_EXPORTS
#    define GUMPP_API __declspec(dllexport)
#  else
#    define GUMPP_API __declspec(dllimport)
#  endif
#else
#  define GUMPP_API
#endif

#define GUMPP_CAPI extern "C" GUMPP_API

#include <vector>

namespace Gum
{
  struct InvocationListener;

  struct Object
  {
    virtual void Retain () = 0;
    virtual void Release () = 0;
    virtual void * GetHandle () const = 0;
  };

  struct PtrArray : public Object
  {
    virtual int Length () = 0;
    virtual void * Nth (int n) = 0;
  };

  template <typename T> class RefPtr
  {
  public:
    explicit RefPtr (T * ptr_) : ptr (ptr_) {}
    explicit RefPtr (const RefPtr<T> & other) : ptr (other.ptr)
    {
      if (ptr)
        ptr->Retain ();
    }

    template <class O> RefPtr (const RefPtr<O> & other) : ptr (other.operator->())
    {
      if (ptr)
        ptr->Retain ();
    }

    RefPtr () : ptr (0) {}

    bool IsNull () const
    {
      return ptr == 0 || ptr->GetHandle () == 0;
    }

    RefPtr & operator = (const RefPtr & other)
    {
      RefPtr tmp (other);
      Swap (*this, tmp);
      return *this;
    }

    RefPtr & operator = (T * other)
    {
      RefPtr tmp (other);
      Swap (*this, tmp);
      return *this;
    }

    T * operator-> () const
    {
      return ptr;
    }

    T & operator* () const
    {
      return *ptr;
    }

    operator T * ()
    {
      return ptr;
    }

    static void Swap (RefPtr & a, RefPtr & b)
    {
      T * tmp = a.ptr;
      a.ptr = b.ptr;
      b.ptr = tmp;
    }

    ~RefPtr ()
    {
      if (ptr)
        ptr->Release ();
    }

  private:
    T * ptr;
  };

  struct SanityChecker
  {
    virtual void Begin (unsigned int flags) = 0;
    virtual bool End () = 0;
  };

  GUMPP_CAPI SanityChecker * SanityCheckerCreate (void);
  GUMPP_CAPI void SanityCheckerDestroy (SanityChecker * checker);

  enum SanityCheckFlags
  {
    CHECK_INSTANCE_LEAKS  = (1 << 0),
    CHECK_BLOCK_LEAKS     = (1 << 1),
    CHECK_BOUNDS          = (1 << 2)
  };

  struct Interceptor : public Object
  {
    virtual bool AttachListener (void * function_address, InvocationListener * listener, void * user_data = 0) = 0;
    virtual void DetachListener (InvocationListener * listener) = 0;
  };

  GUMPP_CAPI Interceptor * InterceptorObtain (void);

  struct InvocationListener : public Object
  {
    virtual void OnEnter (void * user_data) = 0;
    virtual void OnLeave (void * user_data) = 0;
  };

  struct InvocationListenerCallbacks
  {
    virtual void OnEnter (void * user_data) = 0;
    virtual void OnLeave (void * user_data) = 0;
  };

  GUMPP_CAPI InvocationListener * InvocationListenerProxyCreate (InvocationListenerCallbacks * callbacks);

  GUMPP_CAPI void * FindFunctionAsPtr (const char * str);
  GUMPP_CAPI PtrArray * FindFunctionsMatchingAsPtrArray (const char * str);

  class SymbolUtil
  {
  public:
    static void * FindFunction (const char * name)
    {
      return FindFunctionAsPtr (name);
    }

    static std::vector<void *> FindFunctionsMatching (const char * str)
    {
      RefPtr<PtrArray> functions = RefPtr<PtrArray> (FindFunctionsMatchingAsPtrArray (str));
      std::vector<void *> result;
      for (int i = functions->Length () - 1; i >= 0; i--)
        result.push_back (functions->Nth (i));
      return result;
    }
  };
}

#endif