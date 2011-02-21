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

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/xep/xibb/handler/CStreamCloseHandler.h>

using namespace std;

CStreamCloseHandler::CStreamCloseHandler()
{
	try
	{
		// we build the stream close handler
		CXMLFilter* pStreamFilter = new CXMLFilter("iq");
		pStreamFilter->SetAttribut("type", "set");

		CXMLFilter* pSubStreamFilter = new CXMLFilter("stream-close");
		pSubStreamFilter->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");

		pStreamFilter->PushChild(pSubStreamFilter);

		AddXMLFilter(pStreamFilter);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamCloseHandlerException(CStreamCloseHandlerException::SCHEC_CONSTRUCTORERROR);
	}
}

CStreamCloseHandler::~CStreamCloseHandler()
{
}

CStreamCloseHandlerException::CStreamCloseHandlerException(int code) : CException(code)
{}

CStreamCloseHandlerException::~CStreamCloseHandlerException() throw()
{}
	
const char* CStreamCloseHandlerException::what() const throw()
{
	switch(GetCode())
	{
	case SCHEC_CONSTRUCTORERROR:
		return "CStreamCloseHandler::Constructor() error";
						
	default:
		return "CStreamCloseHandler: Unknown error";
	}
}
