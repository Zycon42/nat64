/**
 * Projekt do predmetu ISA/2011
 *
 * @file callback.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * C++ callback
 */

#ifndef _CALLBACK_H_
#define _CALLBACK_H_

/// Interface for callback body
template <typename _RetType, typename _Parameter>
class ICallBackBody
{
public:
    /// execute callback
    virtual _RetType execute(_Parameter) = 0;
    /// clone body
    virtual ICallBackBody<_RetType, _Parameter>* clone() const = 0;
};

/**
 * Callback body. For method that has 1 param
 * @tparam _Class which class method is
 * @tparam _RetType method return type
 * @tparam _Parameter method parameter
 */
template <class _Class, typename _RetType, typename _Parameter>
class CallBackBody : public ICallBackBody<_RetType, _Parameter>
{
public:
    typedef _RetType (_Class::*_Method)(_Parameter);

    /// Creates callback for method m of class instance i
    CallBackBody(_Class& i, _Method m) : inst(i), method(m) { }

    /// Call callback
    virtual _RetType execute(_Parameter p) {
        return (inst.*method)(p);  // invoke method
    }
    /// Clone instance
    virtual ICallBackBody<_RetType, _Parameter>* clone() const {
        return new CallBackBody<_Class, _RetType, _Parameter>(*this);
    }
private:
    _Class& inst;       /// class instance
    _Method method;     /// member function pointer to _Class method
};

/**
 * C++ callback. Template functor.
 * Callback for method with 1 parameter
 * @tparam _RetType method return type
 * @tparam _Parameter method parameter type
 */
template <typename _RetType, typename _Parameter>
class CallBack
{
public:
    /// Create callback from callback body
    CallBack(ICallBackBody<_RetType, _Parameter>* body) : body(body) { }
    /// copy ctor
    CallBack(const CallBack<_RetType, _Parameter>& other) : body(
        other.body->clone()) { }

        /// dtor
        ~CallBack() { delete body; }
        /// assignment operator
        CallBack<_RetType, _Parameter>& operator=(const CallBack<_RetType, _Parameter>& other) {
            if (&other != this) {           // handle self assignment
            delete body;
            body = other.body->clone();
            }
            return *this;
        }
        /// execute callback
        _RetType operator() (_Parameter p) {
            return body->execute(p);
        }

        /**
         * Create callback of member function.
         * @param i instance of _Class
         * @param m member function pointer of class _Class
         * @return created callback
         */
        template <class _Class, class _Member>
        static CallBack<_RetType, _Parameter> make(_Class& i, _Member m) {
            return CallBack<_RetType, _Parameter>(
                new CallBackBody<_Class, _RetType, _Parameter>(i, m)
            );
        }
private:
    ICallBackBody<_RetType, _Parameter>* body;
};

#endif // _CALLBACK_H_
