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
#include <common/xml/CXMLNode.h>

#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/stream/COpenStanza.h>

using namespace std;

COpenStanza::COpenStanza() : CStanza()
{
	try
	{
		SetName("stream:open");
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw COpenStanzaException(COpenStanzaException::OSEC_CONSTRUCTORERROR);
	}
}

COpenStanza::~COpenStanza()
{
}

CObject::u32 COpenStanza::GetKindOf() const
{
	return SKO_OPEN;
}

void COpenStanza::Build(CBuffer* pBuffer) const
{
	try
	{
		string data = "<stream:stream to='" + GetTo() + "'";
		data += " version='1.0' xmlns:stream='http://etherx.jabber.org/streams'";
		data += " xmlns='jabber:client'>";

		pBuffer->Affect(data);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw COpenStanzaException(COpenStanzaException::OSEC_BUILDERROR);
	}
}


COpenStanzaException::COpenStanzaException(int code) : CException(code)
{}

COpenStanzaException::~COpenStanzaException() throw()
{}

const char* COpenStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case OSEC_CONSTRUCTORERROR:
		return "COpenStanza::Constructor() error";
		
	case OSEC_BUILDERROR:
		return "COpenStanza::Build() error";

	default:
		return "COpenStanza: Unknown error";
	}
}
