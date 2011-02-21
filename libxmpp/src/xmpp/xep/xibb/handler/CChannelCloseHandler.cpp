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
#include <xmpp/xep/xibb/handler/CChannelCloseHandler.h>

using namespace std;

CChannelCloseHandler::CChannelCloseHandler()
{
	try
	{
		// we build the channel close handler
		CXMLFilter* pChannelFilter = new CXMLFilter("iq");
		pChannelFilter->SetAttribut("type", "set");

		CXMLFilter* pSubChannelFilter = new CXMLFilter("channel-close");
		pSubChannelFilter->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");

		pChannelFilter->PushChild(pSubChannelFilter);

		AddXMLFilter(pChannelFilter);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelCloseHandlerException(CChannelCloseHandlerException::CCHEC_CONSTRUCTORERROR);
	}
}

CChannelCloseHandler::~CChannelCloseHandler()
{
}

CChannelCloseHandlerException::CChannelCloseHandlerException(int code) : CException(code)
{}

CChannelCloseHandlerException::~CChannelCloseHandlerException() throw()
{}
	
const char* CChannelCloseHandlerException::what() const throw()
{
	switch(GetCode())
	{
	case CCHEC_CONSTRUCTORERROR:
		return "CChannelCloseHandler::Constructor() error";
						
	default:
		return "CChannelCloseHandler: Unknown error";
	}
}
