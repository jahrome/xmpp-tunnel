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
#include <xmpp/xep/xibb/handler/CChannelDataHandler.h>

using namespace std;

CChannelDataHandler::CChannelDataHandler()
{
}

CChannelDataHandler::CChannelDataHandler(const CJid& rJid, u16 channelId)
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

		throw CChannelDataHandlerException(CChannelDataHandlerException::CDHEC_CONSTRUCTORERROR);
	}
}

void CChannelDataHandler::Init(const CJid& rJid, u16 channelId)
{
	try
	{
		// we convert cid to a string
		ostringstream CidConvertor;
		CidConvertor << channelId;
	
		// we build the channel data handler
		CXMLFilter* pDataFilter = new CXMLFilter("message");
		pDataFilter->SetAttribut("from", rJid.GetFull());

		CXMLFilter* pSubDataFilter = new CXMLFilter("channel-data");
		pSubDataFilter->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");
		pSubDataFilter->SetAttribut("cid", CidConvertor.str());

		pDataFilter->PushChild(pSubDataFilter);

		AddXMLFilter(pDataFilter);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelDataHandlerException(CChannelDataHandlerException::CDHEC_INITERROR);
	}
}

CChannelDataHandler::~CChannelDataHandler()
{
}

CChannelDataHandlerException::CChannelDataHandlerException(int code) : CException(code)
{}

CChannelDataHandlerException::~CChannelDataHandlerException() throw()
{}
	
const char* CChannelDataHandlerException::what() const throw()
{
	switch(GetCode())
	{
	case CDHEC_CONSTRUCTORERROR:
		return "CChannelDataHandler::Constructor() error";
						
	case CDHEC_INITERROR:
		return "CChannelDataHandler::Init() error";
						
	default:
		return "CChannelDataHandler: Unknown error";
	}
}
