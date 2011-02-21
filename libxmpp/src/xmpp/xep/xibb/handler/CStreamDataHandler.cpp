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
#include <xmpp/xep/xibb/handler/CStreamDataHandler.h>

using namespace std;

CStreamDataHandler::CStreamDataHandler()
{
}

CStreamDataHandler::CStreamDataHandler(const CJid& rJid, u16 channelId, u16 streamId)
{
	try
	{
		Init(rJid, channelId, streamId);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamDataHandlerException(CStreamDataHandlerException::SDHEC_CONSTRUCTORERROR);
	}
}

void CStreamDataHandler::Init(const CJid& rJid, u16 channelId, u16 streamId)
{
	try
	{
		// we convert cid and sid to a string
		ostringstream CidConvertor;
		ostringstream SidConvertor;
		
		CidConvertor << channelId;
		SidConvertor << streamId;
	
		// we build the channel data handler
		CXMLFilter* pDataFilter = new CXMLFilter("message");
		pDataFilter->SetAttribut("from", rJid.GetFull());

		CXMLFilter* pSubDataFilter = new CXMLFilter("stream-data");
		pSubDataFilter->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");
		pSubDataFilter->SetAttribut("cid", CidConvertor.str());
		pSubDataFilter->SetAttribut("sid", SidConvertor.str());

		pDataFilter->PushChild(pSubDataFilter);

		AddXMLFilter(pDataFilter);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamDataHandlerException(CStreamDataHandlerException::SDHEC_INITERROR);
	}
}

CStreamDataHandler::~CStreamDataHandler()
{
}

CStreamDataHandlerException::CStreamDataHandlerException(int code) : CException(code)
{}

CStreamDataHandlerException::~CStreamDataHandlerException() throw()
{}
	
const char* CStreamDataHandlerException::what() const throw()
{
	switch(GetCode())
	{
	case SDHEC_CONSTRUCTORERROR:
		return "CStreamDataHandler::Constructor() error";
						
	case SDHEC_INITERROR:
		return "CStreamDataHandler::Init() error";
						
	default:
		return "CStreamDataHandler: Unknown error";
	}
}
