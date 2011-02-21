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

#ifndef __CRESPONSESTANZA_H__
#define __CRESPONSESTANZA_H__

#include <string>

#include <openssl/md5.h>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/CStanza.h>

using namespace std;

class CResponseStanza : public CStanza
{
public:
	CResponseStanza();
	virtual ~CResponseStanza();

	u32 GetKindOf() const;
	
	void SetValues(const CJid& rJid, const string& realm, const string& nonce,
					const string& qop, const string& algorithm);

private:
	void Start();
	void Append(const CBuffer* pBuffer);
	void Finish(u8* result);
	void ToHex(u8* plain, u8* hex);
	MD5_CTX ctx;
	
};

class CResponseStanzaException : public CException
{
public:
	enum ResponseStanzaExceptionCode
	{
		RSEC_CONSTRUCTORERROR,
		RSEC_SETVALUESERROR
	};

public:
	CResponseStanzaException(int code);
	virtual ~CResponseStanzaException() throw();

	virtual const char* what() const throw();
};
 
#endif // __CRESPONSESTANZA_H__
