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

#include <pthread.h>
#include <iostream>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/thread/CMutex.h>

using namespace std;

CMutex::CMutex()
{
	Init();
}

CMutex::~CMutex()
{
	try
	{
		Destroy();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}
void CMutex::ReInit()
{
	Destroy();
	Init();
}

void CMutex::Lock()
{
	try
	{
		if(pthread_mutex_lock(&mutex) != 0)
		throw CMutexException(CMutexException::MEC_LOCKERROR);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CMutexException(CMutexException::MEC_LOCKERROR);
	}
}

void CMutex::UnLock()
{
	try
	{
		if(pthread_mutex_unlock(&mutex) != 0)
		throw CMutexException(CMutexException::MEC_UNLOCKERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CMutexException(CMutexException::MEC_UNLOCKERROR);
	}
}

bool CMutex::TryLock()
{
	return pthread_mutex_trylock(&mutex) == 0;
}

bool CMutex::Wait()
{
	try
	{
		if(pthread_cond_wait(&cond, &mutex) != 0)
		throw CMutexException(CMutexException::MEC_WAITERROR);
		
		return isDestroyed == false;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CMutexException(CMutexException::MEC_WAITERROR);
	}
}

void CMutex::Signal()
{
	try
	{
		if(pthread_cond_broadcast(&cond) != 0)
		throw CMutexException(CMutexException::MEC_SIGNALERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CMutexException(CMutexException::MEC_SIGNALERROR);
	}
}

void CMutex::SignalDestroy()
{
	isDestroyed = true;
	
	if(pthread_cond_broadcast(&cond) != 0)
	throw CMutexException(CMutexException::MEC_SIGNALERROR);
}

void CMutex::Init()
{
	try
	{
		isDestroyed = false;

		if(pthread_mutex_init(&mutex, NULL) != 0)
		throw CMutexException(CMutexException::MEC_INITERROR);
	
		if(pthread_cond_init(&cond, NULL) != 0)
		{
			pthread_mutex_destroy(&mutex);
			throw CMutexException(CMutexException::MEC_INITERROR);
		}
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CMutexException(CMutexException::MEC_INITERROR);
	}
}

void CMutex::Destroy()
{
	try
	{
		if(pthread_mutex_destroy(&mutex) != 0 || pthread_cond_destroy(&cond) != 0)
		throw CMutexException(CMutexException::MEC_DESTROYERROR);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CMutexException(CMutexException::MEC_DESTROYERROR);
	}
}

CMutexException::CMutexException(int code) : CException(code)
{}

CMutexException::~CMutexException() throw()
{}
	
const char* CMutexException::what() const throw()
{
	switch(GetCode())
	{
	case MEC_REINITERROR:
		return "CMutex::ReInit() error";
		
	case MEC_INITERROR:
		return "CMutex::Init() error";
		
	case MEC_DESTROYERROR:
		return "CMutex::Destroy() error";

	case MEC_LOCKERROR:
		return "CMutex::Lock() error";

	case MEC_UNLOCKERROR:
		return "CMutex::Unlock() error";

	case MEC_SIGNALERROR:
		return "CMutex::Signal() error";

	case MEC_WAITERROR:
		return "CMutex::Wait() error";

	default:
		return "CMutex:Unknown error";
	}
}
