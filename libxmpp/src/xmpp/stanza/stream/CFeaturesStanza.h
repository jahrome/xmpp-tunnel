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

#ifndef __CFEATURESSTANZA_H__
#define __CFEATURESSTANZA_H__

#include <string>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/stanza/CStanza.h>

using namespace std;

class CFeaturesStanza : public CStanza
{
public:
	enum SaslMechanisms
	{
		SASLM_NONE   = 0x00,
		SASLM_GOOGLE = 0x01,
		SASLM_PLAIN  = 0x02,
		SASLM_DIGEST = 0x04
	};

	CFeaturesStanza();
	virtual ~CFeaturesStanza();
	
	u32 GetKindOf() const;
	
	bool IsTLSRequired();
	u32 GetSASLMechanisms();
	bool IsBindRequired();
	bool IsSessionRequired();
};

class CFeaturesStanzaException : public CException
{
public:
	enum FeaturesStanzaExceptionCode
	{
		FSEC_CONSTRUCTORERROR,
		FSEC_ISTLSREQUIREDERROR,
		FSEC_GETSASLMECHANISMSERROR,
		FSEC_ISBINDREQUIREDERROR,
		FSEC_ISSESSIONREQUIREDERROR
	};

public:
	CFeaturesStanzaException(int code);
	virtual ~CFeaturesStanzaException() throw();

	virtual const char* what() const throw();
};
 
#endif // __CFEATURESSTANZA_H__
