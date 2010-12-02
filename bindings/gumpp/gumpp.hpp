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
    virtual void ref () = 0;
    virtual void unref () = 0;
    virtual void * get_handle () const = 0;
  };

  struct PtrArray : public Object
  {
    virtual int length () = 0;
    virtual void * nth (int n) = 0;
  };

  struct SanityChecker : public Object
  {
    virtual void begin (unsigned int flags) = 0;
    virtual bool end () = 0;
  };

  GUMPP_CAPI SanityChecker * SanityChecker_new (void);

  enum SanityCheckFlags
  {
    CHECK_INSTANCE_LEAKS  = (1 << 0),
    CHECK_BLOCK_LEAKS     = (1 << 1),
    CHECK_BOUNDS          = (1 << 2)
  };

  struct Interceptor : public Object
  {
    virtual bool attach_listener (void * function_address, InvocationListener * listener, void * user_data = 0) = 0;
    virtual void detach_listener (InvocationListener * listener) = 0;
  };

  GUMPP_CAPI Interceptor * Interceptor_obtain (void);

  struct InvocationListener : public Object
  {
    virtual void on_enter (void * user_data) = 0;
    virtual void on_leave (void * user_data) = 0;
  };

  struct InvocationListenerCallbacks
  {
    virtual void on_enter (void * user_data) = 0;
    virtual void on_leave (void * user_data) = 0;
  };

  GUMPP_CAPI InvocationListener * InvocationListenerProxy_new (InvocationListenerCallbacks * callbacks);

  GUMPP_CAPI void * find_function_ptr (const char * str);
  GUMPP_CAPI PtrArray * find_matching_functions_array (const char * str);

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
        ptr->ref ();
    }

    RefPtr () : ptr (0) {}

    bool is_null () const
    {
      return ptr == 0 || ptr->get_handle () == 0;
    }

    RefPtr & operator = (const RefPtr & other)
    {
      RefPtr tmp (other);
      swap (*this, tmp);
      return *this;
    }

    RefPtr & operator = (T * other)
    {
      RefPtr tmp (other);
      swap (*this, tmp);
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

    static void swap (RefPtr & a, RefPtr & b)
    {
      T * tmp = a.ptr;
      a.ptr = b.ptr;
      b.ptr = tmp;
    }

    ~RefPtr ()
    {
      if (ptr)
        ptr->unref ();
    }

  private:
    T * ptr;
  };

  class SymbolUtil
  {
  public:
    static void * find_function (const char * name)
    {
      return find_function_ptr (name);
    }

    static std::vector<void *> find_matching_functions (const char * str)
    {
      RefPtr<PtrArray> functions = RefPtr<PtrArray> (find_matching_functions_array (str));
      std::vector<void *> result;
      for (int i = functions->length () - 1; i >= 0; i--)
        result.push_back (functions->nth (i));
      return result;
    }
  };
}

#endif