/*
 *  XMPP-SSH is a XMPP protocol extension to provide several secure shell
 *  streams over the XMPP protocol between two Jabber entities using
 *  strong authentication, end-To-end encryption (RSA/AES) and X11
 *  forwarding.
 *
 *  Copyright (C) 2007 Adrien Pinet
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */

#ifndef __CTHREAD_H__
#define __CTHREAD_H__

#include <pthread.h>

#include <common/CException.h>
#include <common/CObject.h>

class CThread : CObject
{
public:
	CThread();
	virtual ~CThread();

public:
	static void RunDetached(void* (pThread)(void*), void* pThreadParam);

	void Run(void* (pThread)(void*), void* pThreadParam);
	void Wait();
	void Stop();

	bool IsRunning() {return isRunning;}

private:
	pthread_t thread;
	pthread_attr_t threadAttr;
	bool isRunning;
};

class CThreadException : public CException
{
public:
	enum ThreadExceptionCode
	{
		TEC_RUNERROR,
		TEC_RUNDETACHEDERROR,
		TEC_WAITERROR,
		TEC_STOPERROR
	};

public:
	CThreadException(int code);
	virtual ~CThreadException() throw();

	virtual const char* what() const throw();
};
 
#endif // __CTHREAD_H__
