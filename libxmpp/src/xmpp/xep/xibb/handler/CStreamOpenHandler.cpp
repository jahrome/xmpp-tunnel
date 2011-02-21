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
#include <xmpp/xep/xibb/handler/CStreamOpenHandler.h>

using namespace std;

CStreamOpenHandler::CStreamOpenHandler()
{
}

CStreamOpenHandler::CStreamOpenHandler(const CJid& rJid, u16 channelId)
{
	try
	{
		Init(rJid, channelId);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamOpenHandlerException(CStreamOpenHandlerException::SOHEC_CONSTRUCTORERROR);
	}
}

void CStreamOpenHandler::Init(const CJid& rJid, u16 channelId)
{
	try
	{
		// we convert cid to a string
		ostringstream CidConvertor;
		CidConvertor << channelId;
	
		// we build the channel open handler
		CXMLFilter* pFilter = new CXMLFilter("iq");
		pFilter->SetAttribut("type", "set");
		pFilter->SetAttribut("from", rJid.GetFull());

		CXMLFilter* pSubFilter = new CXMLFilter("stream-open");
		pSubFilter->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");
		pSubFilter->SetAttribut("cid", CidConvertor.str());

		pFilter->PushChild(pSubFilter);

		AddXMLFilter(pFilter);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamOpenHandlerException(CStreamOpenHandlerException::SOHEC_INITERROR);
	}
}

CStreamOpenHandler::~CStreamOpenHandler()
{
}

CStreamOpenHandlerException::CStreamOpenHandlerException(int code) : CException(code)
{}

CStreamOpenHandlerException::~CStreamOpenHandlerException() throw()
{}
	
const char* CStreamOpenHandlerException::what() const throw()
{
	switch(GetCode())
	{
	case SOHEC_CONSTRUCTORERROR:
		return "CStreamOpenHandler::Constructor() error";
						
	default:
		return "CStreamOpenHandler: Unknown error";
	}
}
