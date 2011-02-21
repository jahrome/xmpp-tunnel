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
#include <sstream>
#include <string>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/xep/xibb/handler/CPresenceHandler.h>

using namespace std;

CPresenceHandler::CPresenceHandler()
{
	try
	{
		// we build the presence unavailable handler
		CXMLFilter* pFilter = new CXMLFilter("presence");
		pFilter->SetAttribut("type", "unavailable");

		AddXMLFilter(pFilter);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CPresenceHandlerException(CPresenceHandlerException::PHEC_CONSTRUCTORERROR);
	}
}

CPresenceHandler::~CPresenceHandler()
{
}

CPresenceHandlerException::CPresenceHandlerException(int code) : CException(code)
{}

CPresenceHandlerException::~CPresenceHandlerException() throw()
{}
	
const char* CPresenceHandlerException::what() const throw()
{
	switch(GetCode())
	{
	case PHEC_CONSTRUCTORERROR:
		return "CPresenceHandler::Constructor() error";
						
	default:
		return "CPresenceHandler: Unknown error";
	}
}
