/**
 * Projekt do predmetu ISA/2011
 *
 * @file log.h
 * @author Jan Dušek <xdusek17@stud.fit.vutbr.cz>
 * @date 2011
 *
 * Loging functions
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <iostream>

/**
 * Returns stream used for logging.
 * This function prints time elapsed from first call of this function to logging stream
 * @return logging stream
 */
std::ostream& pLog();

/**
 * Returns stream used for error messages.
 * This function prints time elapsed from first call of this function to error stream
 * @return error stream
 */
std::ostream& pError();

#endif // _LOG_H_
