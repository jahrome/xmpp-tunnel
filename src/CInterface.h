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

#ifndef __CINTERFACE_H__
#define __CINTERFACE_H__

#include <iostream>
#include <string>
#include <curses.h>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/thread/CThread.h>

#include <resox/CResox.h>

#include <xmpp/im/CRoster.h>
#include <xmpp/jid/CJid.h>

using namespace std;

class CInterface : public CObject
{
public:
	CInterface(CResox* pResox);
	virtual ~CInterface();

	const CJid& SelectHost();

	static void RequestPassword(const string& message, string& password);
	static void RequestString(const string& message, string& password);

protected:
	static void* DisplayHostJob(void* pvThis) throw();

private:
	CResox* pResox;
	CJid Jid;
	CRoster Roster;
	CThread ThreadDisplayHostJob;
	CMutex MutexOnDisplay;
	WINDOW* pWinHostList;
	WINDOW* pMainWin;
};

class CInterfaceException : public CException
{
public:
	enum InterfaceExceptionCode
	{
		IEC_CONSTRUCTORERROR
	};

public:
	CInterfaceException(int code);
	virtual ~CInterfaceException() throw();

	virtual const char* what() const throw();
};

#endif //__CINTERFACE_H__
