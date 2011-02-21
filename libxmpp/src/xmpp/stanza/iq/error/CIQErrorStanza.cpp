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

#include <xmpp/stanza/iq/CIQStanza.h>
#include <xmpp/stanza/iq/error/CIQErrorStanza.h>

using namespace std;

CIQErrorStanza::CIQErrorStanza() : CIQStanza()
{
	try
	{
		SetType("error");
	}

	catch(exception& e)
	{
		throw CIQErrorStanzaException(CIQErrorStanzaException::IQESEC_CONSTRUCTORERROR);
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

CIQErrorStanza::~CIQErrorStanza()
{
}

CObject::u32 CIQErrorStanza::GetKindOf() const
{
	return SIQKO_ERROR;
}

CIQErrorStanzaException::CIQErrorStanzaException(int code) : CException(code)
{}

CIQErrorStanzaException::~CIQErrorStanzaException() throw()
{}


const char* CIQErrorStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case IQESEC_CONSTRUCTORERROR:
		return "CIQErrorStanza::Constructor() error";
		
	default:
		return "CIQErrorStanza: Unknown error";
	}
}
