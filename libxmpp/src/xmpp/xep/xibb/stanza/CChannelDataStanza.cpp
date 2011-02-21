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

#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/message/CMessageStanza.h>
#include <xmpp/xep/xibb/stanza/CChannelDataStanza.h>

using namespace std;

CChannelDataStanza::CChannelDataStanza()
{
}

CChannelDataStanza::CChannelDataStanza(const CJid& rRemoteJid, u16 channelId)
{
	try
	{
		Init(rRemoteJid, channelId);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelDataStanzaException(CChannelDataStanzaException::CDSEC_CONSTRUCTORERROR);
	}
}

void CChannelDataStanza::Init(const CJid& rRemoteJid, u16 channelId)
{
	try
	{
		// we convert cid to a string
		ostringstream CidConvertor;
		
		CidConvertor << channelId;
	
		SetTo(rRemoteJid.GetFull());

		CXMLNode* pSubNode;

		if(!IsExistChild("channel-data"))
		{
			pSubNode = new CXMLNode("channel-data");
			PushChild(pSubNode);
		}
		else
		pSubNode = GetChild("channel-data");
		
		pSubNode->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");
		pSubNode->SetAttribut("cid", CidConvertor.str());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelDataStanzaException(CChannelDataStanzaException::CDSEC_INITERROR);
	}
}

CChannelDataStanza::~CChannelDataStanza()
{
}

const string& CChannelDataStanza::GetRemoteJid() const
{
	try
	{
		return GetFrom();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelDataStanzaException(CChannelDataStanzaException::CDSEC_GETREMOTEJIDERROR);
	}
}

CObject::u16 CChannelDataStanza::GetChannelId() const
{
	try
	{
		istringstream CidConvertor(GetChild("channel-data")->GetAttribut("cid"));
		u16 channelId;
		
		CidConvertor >> channelId;
		
		return channelId;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelDataStanzaException(CChannelDataStanzaException::CDSEC_GETCHANNELIDERROR);
	}
}

CChannelDataStanzaException::CChannelDataStanzaException(int code) : CException(code)
{}

CChannelDataStanzaException::~CChannelDataStanzaException() throw()
{}
	
const char* CChannelDataStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case CDSEC_CONSTRUCTORERROR:
		return "CChannelDataStanza::Constructor() error";
						
	case CDSEC_INITERROR:
		return "CChannelDataStanza::Init() error";

	case CDSEC_GETREMOTEJIDERROR:
		return "CChannelDataStanza::GetRemoteJid() error";

	case CDSEC_GETCHANNELIDERROR:
		return "CChannelDataStanza::GetChannelId() error";

	default:
		return "CChannelDataStanza: Unknown error";
	}
}
