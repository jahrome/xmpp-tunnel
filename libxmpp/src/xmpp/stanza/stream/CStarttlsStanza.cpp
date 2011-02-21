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
#include <common/xml/CXMLNode.h>

#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/stream/CStarttlsStanza.h>

using namespace std;

CStarttlsStanza::CStarttlsStanza() : CStanza()
{
	try
	{
		SetName("starttls");
		SetNameSpace("urn:ietf:params:xml:ns:xmpp-tls");
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStarttlsStanzaException(CStarttlsStanzaException::SSEC_CONSTRUCTORERROR);
	}

}

CStarttlsStanza::~CStarttlsStanza()
{
}

CObject::u32 CStarttlsStanza::GetKindOf() const
{
	return SKO_STARTTLS;
}

CStarttlsStanzaException::CStarttlsStanzaException(int code) : CException(code)
{}

CStarttlsStanzaException::~CStarttlsStanzaException() throw()
{}

const char* CStarttlsStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case SSEC_CONSTRUCTORERROR:
		return "CStarttlsStanza::Constructor() error";
		
	default:
		return "CStarttlsStanza: Unknown error";
	}
}
