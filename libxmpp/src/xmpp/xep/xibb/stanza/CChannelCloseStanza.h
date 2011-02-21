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

#ifndef __CCHANNELCLOSESTANZA_H__
#define __CCHANNELCLOSESTANZA_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/iq/set/CIQSetStanza.h>

using namespace std;

class CChannelCloseStanza : public CIQSetStanza
{
public:
	CChannelCloseStanza();	
	CChannelCloseStanza(const CJid& rRemoteJid, u16 channelId, const string& id);
	virtual ~CChannelCloseStanza();
	
	void Init(const CJid& rRemoteJid, u16 channelId, const string& id);
	
	const string& GetRemoteJid() const;
	u16 GetChannelId() const;
};
 
class CChannelCloseStanzaException : public CException
{
public:
	enum ChannelCloseStanzaExceptionCode
	{
		CCSEC_CONSTRUCTORERROR,
		CCSEC_INITERROR,
		CCSEC_GETREMOTEJIDERROR,
		CCSEC_GETCHANNELIDERROR
	};

public:
	CChannelCloseStanzaException(int code);
	virtual ~CChannelCloseStanzaException() throw();

	virtual const char* what() const throw();
};

#endif // __CCHANNELOPENSTANZA_H__
