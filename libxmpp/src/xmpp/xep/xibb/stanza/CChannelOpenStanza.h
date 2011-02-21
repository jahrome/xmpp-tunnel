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

#ifndef __CCHANNELOPENSTANZA_H__
#define __CCHANNELOPENSTANZA_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/iq/set/CIQSetStanza.h>

using namespace std;

class CChannelOpenStanza : public CIQSetStanza
{
public:
	CChannelOpenStanza();	
	CChannelOpenStanza(const CJid& rRemoteJid, u16 channelId, u16 maxStream, u16 blockSize, u32 byteRate, const string& id);
	virtual ~CChannelOpenStanza();
	
	void Init(const CJid& rRemoteJid, u16 channelId, u16 maxStream, u16 blockSize, u32 byteRate, const string& id);
	
	const string& GetRemoteJid() const;
	u16 GetChannelId() const;
	u16 GetMaxStream() const;
	u16 GetBlockSize() const;
	u32 GetByteRate() const;
};
 
class CChannelOpenStanzaException : public CException
{
public:
	enum ChannelOpenStanzaExceptionCode
	{
		COSEC_CONSTRUCTORERROR,
		COSEC_INITERROR,
		COSEC_GETREMOTEJIDERROR,
		COSEC_GETCHANNELIDERROR,
		COSEC_GETMAXSTREAMERROR,
		COSEC_GETBLOCKSIZEERROR,
		COSEC_GETBYTERATEERROR
	};

public:
	CChannelOpenStanzaException(int code);
	virtual ~CChannelOpenStanzaException() throw();

	virtual const char* what() const throw();
};

#endif // __CCHANNELOPENSTANZA_H__
