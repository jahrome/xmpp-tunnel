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

#ifndef __CXMPPINSTMSG_H__
#define __CXMPPINSTMSG_H__

#include <string>
#include <vector>

#include <common/thread/CMutex.h>
#include <common/thread/CThread.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/core/CXMPPCore.h>
#include <xmpp/im/CRoster.h>

using namespace std;

class CXMPPInstMsg : public CXMPPCore
{
public:
	CXMPPInstMsg();
	virtual ~CXMPPInstMsg();

	bool SendPresenceTo(const CJid* pJid, const string& show, const string& status, const string& priority);
	bool SendPresenceToAll(const string& show, const string& status, const string& priority);
	
	void StartRosterEvent(CRoster* pRoster);
	bool OnRosterUpdated(CRoster* pRoster);
	void StopRosterEvent();

private:
	CHandler OnPresenceHandler;
};
 
class CXMPPInstMsgException : public CException
{
public:
	enum XMPPInstMsgExceptionCode
	{
		XMPPIMEC_CONSTRUCTORERROR,
		XMPPIMEC_DESTRUCTORERROR,
		XMPPIMEC_SENDPRESENCETOERROR,	
		XMPPIMEC_SENDPRESENCETOALLERROR,
		XMPPIMEC_UPDATEROSTERERROR,
		XMPPIMEC_GETROSTERJIDERROR
	};

public:
	CXMPPInstMsgException(int code);
	virtual ~CXMPPInstMsgException() throw();

	virtual const char* what() const throw();
};

#endif // __CXMPPINSTMSG_H__
