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
#include <xmpp/stanza/stream/CCloseStanza.h>

using namespace std;

CCloseStanza::CCloseStanza() : CStanza()
{
	try
	{
		SetName("stream:close");
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CCloseStanzaException(CCloseStanzaException::CSEC_CONSTRUCTORERROR);
	}
}

CCloseStanza::~CCloseStanza()
{
}

CObject::u32 CCloseStanza::GetKindOf() const
{
	return SKO_CLOSE;
}

void CCloseStanza::Build(CBuffer* pBuffer) const
{
	try
	{
		string data = "</stream:stream>";
		pBuffer->Affect(data);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CCloseStanzaException(CCloseStanzaException::CSEC_BUILDERROR);
	}
}

CCloseStanzaException::CCloseStanzaException(int code) : CException(code)
{}

CCloseStanzaException::~CCloseStanzaException() throw()
{}

const char* CCloseStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case CSEC_CONSTRUCTORERROR:
		return "CCloseStanza::Constructor() error";
		
	case CSEC_BUILDERROR:
		return "CCloseStanza::Build() error";

	default:
		return "CCloseStanza: Unknown error";
	}
}
