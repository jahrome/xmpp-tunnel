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

#include <iostream>
#include <string>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/data/CBase64.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/stream/CAuthStanza.h>
#include <xmpp/stanza/CStanza.h>

using namespace std;

CAuthStanza::CAuthStanza() : CStanza()
{
	SetName("auth");
	SetNameSpace("urn:ietf:params:xml:ns:xmpp-sasl");
}

CAuthStanza::~CAuthStanza()
{
}

CObject::u32 CAuthStanza::GetKindOf() const
{
	return SKO_AUTH;
}

void CAuthStanza::SetMechanism(AuthMethod authMethod, const CJid& rJid)
{
	try
	{
		if(authMethod == AM_GOOGLE)
		{
			CBuffer GoogleToken;
			CBase64 Base64;
			string token;
			
			SetAttribut("mechanism", "PLAIN");
			SetAttribut("xmlns:ga", "http://www.google.com/talk/protocol/auth");
			SetAttribut("ga:client-uses-full-bind-result", "true");
			
			GoogleToken.Create(3 + rJid.GetName().size() + rJid.GetHost().size() + rJid.GetPassword().size());
			GoogleToken.Write((char) '\0');
			GoogleToken.Write(rJid.GetName());
			GoogleToken.Write((char) '@');
			GoogleToken.Write(rJid.GetHost());
			GoogleToken.Write((char) '\0');
			GoogleToken.Write(rJid.GetPassword());
			
			Base64.To64(&GoogleToken, token);

			SetData(token.c_str(), token.size());
			return;
		}
		
		if(authMethod == AM_PLAIN)
		{
			SetAttribut("mechanism", "PLAIN");
		}
		
		if(authMethod == AM_DIGEST)
		{
			SetAttribut("mechanism", "DIGEST-MD5");
			return;
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CAuthStanzaException(CAuthStanzaException::ASEC_SETMECHANISMERROR);
	}
}


CAuthStanzaException::CAuthStanzaException(int code) : CException(code)
{}

CAuthStanzaException::~CAuthStanzaException() throw()
{}

const char* CAuthStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case ASEC_CONSTRUCTORERROR:
		return "CAuthStanza::Constructor() error";

	case ASEC_SETMECHANISMERROR:
		return "CAuthStanza:SetMechansim() error";

	default:
		return "CAuthStanza: Unknown error";
	}
}

