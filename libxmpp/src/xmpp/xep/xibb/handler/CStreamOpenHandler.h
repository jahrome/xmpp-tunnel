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

#ifndef __CSTREAMOPENHANDLER_H__
#define __CSTREAMOPENHANDLER_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/jid/CJid.h>

using namespace std;

class CStreamOpenHandler : public CHandler
{
public:
	CStreamOpenHandler();	
	CStreamOpenHandler(const CJid& rJid, u16 channelId);
	virtual ~CStreamOpenHandler();
	
	void Init(const CJid& rJid, u16 channelId);
};
 
class CStreamOpenHandlerException : public CException
{
public:
	enum StreamOpenHandlerExceptionCode
	{
		SOHEC_CONSTRUCTORERROR,
		SOHEC_INITERROR
	};

public:
	CStreamOpenHandlerException(int code);
	virtual ~CStreamOpenHandlerException() throw();

	virtual const char* what() const throw();
};

#endif // __CSTREAMOPENHANDLER_H__
