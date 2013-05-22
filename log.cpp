/**
 * Projekt do predmetu ISA/2011
 *
 * @file log.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Loging functions
 */

#include "log.h"

#include <sys/time.h>

/**
 * Subtracts two timeval values.
 * result = x - y
 * @retval result result of subtraction
 * @param x minuend
 * @param y subtrahend
 * @return 1 if result negative 0 if positive
 */
static int subtractTimeval(timeval* result, timeval* x, timeval* y)
{
    // Perform the carry for the later subtraction by updating y.
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    // Compute the time remaining to wait. tv_usec is certainly positive.
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    return x->tv_sec < y->tv_sec;   // Return 1 if result is negative.
}

/**
 * Get time difference between first and current function call.
 * @return time diff
 */
static timeval getTimeDiff() {
    static timeval firstTime;
    static bool firstRun = true;
    // on first function call get time
    if (firstRun) {
        gettimeofday(&firstTime, NULL);
        firstRun = false;
    }

    // get current time
    timeval curTime, time;
    gettimeofday(&curTime, NULL);

    // subtract time on first run from curent time
    subtractTimeval(&time, &curTime, &firstTime);

    return time;
}

std::ostream& pLog() {
    timeval time = getTimeDiff();

    std::ostream& str = std::clog;
    str << "[" << time.tv_sec << "." << time.tv_usec << "] ";
    return str;
}

std::ostream& pError() {
    timeval time = getTimeDiff();

    std::ostream& str = std::cerr;
    str << "[" << time.tv_sec << "." << time.tv_usec << "] ";
    return str;
}
