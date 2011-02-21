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

#ifndef __CSTREAMDATASTANZA_H__
#define __CSTREAMDATASTANZA_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/message/CMessageStanza.h>

using namespace std;

class CStreamDataStanza : public CMessageStanza
{
public:
	CStreamDataStanza();	
	CStreamDataStanza(const CJid& rRemoteJid, u16 channelId, u16 streamId);
	virtual ~CStreamDataStanza();
	
	void Init(const CJid& rRemoteJid, u16 channelId, u16 streamId);
	
	const string& GetRemoteJid() const;
	u16 GetChannelId() const;
	u16 GetStreamId() const;
};
 
class CStreamDataStanzaException : public CException
{
public:
	enum StreamDataStanzaExceptionCode
	{
		SDSEC_CONSTRUCTORERROR,
		SDSEC_INITERROR,
		SDSEC_GETREMOTEJIDERROR,
		SDSEC_GETCHANNELIDERROR,
		SDSEC_GETSTREAMIDERROR
	};

public:
	CStreamDataStanzaException(int code);
	virtual ~CStreamDataStanzaException() throw();

	virtual const char* what() const throw();
};

#endif // __CSTREAMDATASTANZA_H__
