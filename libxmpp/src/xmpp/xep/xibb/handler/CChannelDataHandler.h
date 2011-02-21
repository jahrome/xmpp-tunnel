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

#ifndef __CCHANNELDATAHANDLER_H__
#define __CCHANNELDATAHANDLER_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/jid/CJid.h>

using namespace std;

class CChannelDataHandler : public CHandler
{
public:
	CChannelDataHandler();
	CChannelDataHandler(const CJid& rJid, u16 channelId);
	virtual ~CChannelDataHandler();
	
	void Init(const CJid& rJid, u16 channelId);
};
 
class CChannelDataHandlerException : public CException
{
public:
	enum ChannelDataHandlerExceptionCode
	{
		CDHEC_CONSTRUCTORERROR,
		CDHEC_INITERROR
	};

public:
	CChannelDataHandlerException(int code);
	virtual ~CChannelDataHandlerException() throw();

	virtual const char* what() const throw();
};

#endif // __CCHANNELDATAHANDLER_H__
