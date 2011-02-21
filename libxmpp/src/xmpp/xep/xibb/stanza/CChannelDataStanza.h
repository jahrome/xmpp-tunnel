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

#ifndef __CCHANNELDATASTANZA_H__
#define __CCHANNELDATASTANZA_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/message/CMessageStanza.h>

using namespace std;

class CChannelDataStanza : public CMessageStanza
{
public:
	CChannelDataStanza();	
	CChannelDataStanza(const CJid& rRemoteJid, u16 channelId);
	virtual ~CChannelDataStanza();
	
	void Init(const CJid& rRemoteJid, u16 channelId);
	
	const string& GetRemoteJid() const;
	u16 GetChannelId() const;
};
 
class CChannelDataStanzaException : public CException
{
public:
	enum ChannelDataStanzaExceptionCode
	{
		CDSEC_CONSTRUCTORERROR,
		CDSEC_INITERROR,
		CDSEC_GETREMOTEJIDERROR,
		CDSEC_GETCHANNELIDERROR
	};

public:
	CChannelDataStanzaException(int code);
	virtual ~CChannelDataStanzaException() throw();

	virtual const char* what() const throw();
};

#endif // __CCHANNELDATASTANZA_H__
