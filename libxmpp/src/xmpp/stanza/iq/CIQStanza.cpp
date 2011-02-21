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
#include <xmpp/stanza/iq/CIQStanza.h>

using namespace std;

CIQStanza::CIQStanza() : CStanza()
{
	try
	{
		SetName("iq");
	}

	catch(exception& e)
	{
		throw CIQStanzaException(CIQStanzaException::IQSEC_CONSTRUCTORERROR);
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

CIQStanza::~CIQStanza()
{
}

CObject::u32 CIQStanza::GetKindOf() const
{
	try
	{
		if(GetType() == "get")
		return SIQKO_GET;

		if(GetType() == "result")
		return SIQKO_RESULT;

		if(GetType() == "set")
		return SIQKO_SET;
		
		return SIQKO_UNKNOWN;
	}

	catch(exception& e)
	{
		throw CIQStanzaException(CIQStanzaException::IQSEC_GETKINDOFERROR);
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

CIQStanzaException::CIQStanzaException(int code) : CException(code)
{}

CIQStanzaException::~CIQStanzaException() throw()
{}


const char* CIQStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case IQSEC_CONSTRUCTORERROR:
		return "CIQStanza::Constructor() error";

	case IQSEC_GETKINDOFERROR:
		return "CIQStanza::GetKindOf() error";

	default:
		return "CIQStanza: Unknown error";
	}
}
