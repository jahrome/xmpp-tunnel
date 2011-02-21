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

#ifndef __CSTREAMDATAHANDLER_H__
#define __CSTREAMDATAHANDLER_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/jid/CJid.h>

using namespace std;

class CStreamDataHandler : public CHandler
{
public:
	CStreamDataHandler();	
	CStreamDataHandler(const CJid& rJid, u16 channelId, u16 streamId);
	virtual ~CStreamDataHandler();
	
	void Init(const CJid& rJid, u16 channelId, u16 streamId);
};
 
class CStreamDataHandlerException : public CException
{
public:
	enum StreamDataHandlerExceptionCode
	{
		SDHEC_CONSTRUCTORERROR,
		SDHEC_INITERROR
	};

public:
	CStreamDataHandlerException(int code);
	virtual ~CStreamDataHandlerException() throw();

	virtual const char* what() const throw();
};

#endif // __CSTREAMDATAHANDLER_H__
