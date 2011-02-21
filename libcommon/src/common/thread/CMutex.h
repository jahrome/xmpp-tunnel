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

#ifndef __CMUTEX_H__
#define __CMUTEX_H__

#include <pthread.h>

#include <common/CException.h>
#include <common/CObject.h>

class CMutex : public CObject
{
public:
	CMutex();
	virtual ~CMutex();

public:
	void ReInit();

	void Lock();
	void UnLock();
	bool TryLock();
	
	bool Wait();
	void Signal();
	void SignalDestroy();

private:
	void Init();
	void Destroy();
	
private:
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool isDestroyed;
};
 
class CMutexException : public CException
{
public:
	enum MutexExceptionCode
	{
		MEC_INITERROR,
		MEC_REINITERROR,
		MEC_DESTROYERROR,
		MEC_LOCKERROR,
		MEC_UNLOCKERROR,
		MEC_SIGNALERROR,
		MEC_WAITERROR
	};

public:
	CMutexException(int code);
	virtual ~CMutexException() throw();

	virtual const char* what() const throw();
};

#endif // __CMUTEX_H__
