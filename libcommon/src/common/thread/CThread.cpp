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

#include <iostream>
#include <pthread.h>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/thread/CThread.h>

using namespace std;

CThread::CThread()
{
	isRunning = false;
}

CThread::~CThread()
{
	try
	{
		Wait();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

void CThread::RunDetached(void* (pThread)(void*), void* pThreadParam)
{
	try
	{
		pthread_t thread;
		pthread_attr_t threadAttr;

		if(pthread_attr_init(&threadAttr) != 0)
		throw CThreadException(CThreadException::TEC_RUNERROR);
		
		pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED);
		
		if(pthread_create(&thread, &threadAttr, pThread, pThreadParam) != 0)
		{
			pthread_attr_destroy(&threadAttr);
			throw CThreadException(CThreadException::TEC_RUNERROR);
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CThreadException(CThreadException::TEC_RUNDETACHEDERROR);
	}
}

void CThread::Run(void* (pThread)(void*), void* pThreadParam)
{
	try
	{
		if(IsRunning())
		return;

		if(pThread == NULL)
		throw CThreadException(CThreadException::TEC_RUNERROR);
		
		if(pthread_attr_init(&threadAttr) != 0)
		throw CThreadException(CThreadException::TEC_RUNERROR);
		
		if(pthread_create(&thread, &threadAttr, pThread, pThreadParam) != 0)
		{
			pthread_attr_destroy(&threadAttr);
			throw CThreadException(CThreadException::TEC_RUNERROR);
		}
		
		isRunning = true;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CThreadException(CThreadException::TEC_RUNERROR);
	}
}

void CThread::Wait()
{
	try
	{
		if(!IsRunning())
		return;

		isRunning = false;

		int retJoin = pthread_join(thread, NULL);
		int retDestroy = pthread_attr_destroy(&threadAttr);
		
		if(retJoin != 0 || retDestroy != 0)
		throw CThreadException(CThreadException::TEC_WAITERROR);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CThreadException(CThreadException::TEC_WAITERROR);
	}
}

void CThread::Stop()
{
	try
	{
		if(!IsRunning())
		return;

#ifndef __ANDROID__
		pthread_cancel(thread);
#endif// __ANDROID__
		Wait();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CThreadException(CThreadException::TEC_STOPERROR);
	}
}


CThreadException::CThreadException(int code) : CException(code)
{}

CThreadException::~CThreadException() throw()
{}

const char* CThreadException::what() const throw()
{
	switch(GetCode())
	{
	case TEC_RUNERROR:
		return "CThread::Run() error";
		
	case TEC_RUNDETACHEDERROR:
		return "CThread::RunDetached() error";
		
	case TEC_WAITERROR:
		return "CThread::Wait() error";

	case TEC_STOPERROR:
		return "CThread::Stop() error";

	default:
		return "CThread: Unknown error";
	}
}
