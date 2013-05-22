/**
 * Projekt do predmetu ISA/2011
 *
 * @file exceptions.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Exception classes
 */

#ifndef _EXCEPTIONS_H_
#define _EXCEPTIONS_H_

#include <stdexcept>
#include <string.h>

/**
 * exception for system calls
 * uses strerror function to get proper message describing error
 */
class system_error : public std::exception
{
public:
    /// parameterless ctor
    system_error() throw() { }
    /// destructor
    virtual ~system_error() throw() { }
    /**
     * Constructs system_error object from optional string and errnum
     * if str is NULL then what() = strerror(errnum) else what() = str + ": " + strerror(errnum)
     * @param str optional parameter
     * @param errnum describing error. see errno
     */
    system_error(const char* str, int errnum) {
        if (str != NULL)
            msg = std::string(str) + std::string(": ") + strerror(errnum);
        else
            msg = strerror(errnum);
    }

    /// Gets coresponding error message
    virtual const char * what() const throw() {
        return msg.c_str();
    }
private:
    std::string msg;
};

#endif // _EXCEPTIONS_H_
