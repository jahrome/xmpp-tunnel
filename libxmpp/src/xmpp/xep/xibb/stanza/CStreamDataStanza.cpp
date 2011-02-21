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
#include <xmpp/xep/xibb/stanza/CStreamDataStanza.h>

using namespace std;

CStreamDataStanza::CStreamDataStanza()
{
}

CStreamDataStanza::CStreamDataStanza(const CJid& rRemoteJid, u16 channelId, u16 streamId)
{
	try
	{
		Init(rRemoteJid, channelId, streamId);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamDataStanzaException(CStreamDataStanzaException::SDSEC_CONSTRUCTORERROR);
	}
}

void CStreamDataStanza::Init(const CJid& rRemoteJid, u16 channelId, u16 streamId)
{
	try
	{
		// we convert cid and sid to a string
		ostringstream CidConvertor;
		ostringstream SidConvertor;
		
		CidConvertor << channelId;
		SidConvertor << streamId;
	
		SetTo(rRemoteJid.GetFull());
		
		CXMLNode* pSubNode;
		
		if(!IsExistChild("stream-data"))
		{
			pSubNode = new CXMLNode("stream-data");
			PushChild(pSubNode);
		}
		else
		pSubNode = GetChild("stream-data");
		
		
		pSubNode->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");
		pSubNode->SetAttribut("cid", CidConvertor.str());
		pSubNode->SetAttribut("sid", SidConvertor.str());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamDataStanzaException(CStreamDataStanzaException::SDSEC_INITERROR);
	}
}

CStreamDataStanza::~CStreamDataStanza()
{
}

const string& CStreamDataStanza::GetRemoteJid() const
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

		throw CStreamDataStanzaException(CStreamDataStanzaException::SDSEC_GETREMOTEJIDERROR);
	}
}

CObject::u16 CStreamDataStanza::GetChannelId() const
{
	try
	{
		istringstream CidConvertor(GetChild("stream-data")->GetAttribut("cid"));
		u16 channelId;
		
		CidConvertor >> channelId;
		
		return channelId;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamDataStanzaException(CStreamDataStanzaException::SDSEC_GETCHANNELIDERROR);
	}
}

CObject::u16 CStreamDataStanza::GetStreamId() const
{
	try
	{
		istringstream SidConvertor(GetChild("stream-data")->GetAttribut("sid"));
		u16 streamId;
		
		SidConvertor >> streamId;
		
		return streamId;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamDataStanzaException(CStreamDataStanzaException::SDSEC_GETSTREAMIDERROR);
	}
}

CStreamDataStanzaException::CStreamDataStanzaException(int code) : CException(code)
{}

CStreamDataStanzaException::~CStreamDataStanzaException() throw()
{}
	
const char* CStreamDataStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case SDSEC_CONSTRUCTORERROR:
		return "CStreamDataStanza::Constructor() error";
						
	case SDSEC_INITERROR:
		return "CStreamDataStanza::Init() error";

	case SDSEC_GETREMOTEJIDERROR:
		return "CStreamDataStanza::GetRemoteJid() error";

	case SDSEC_GETCHANNELIDERROR:
		return "CStreamDataStanza::GetChannelId() error";

	case SDSEC_GETSTREAMIDERROR:
		return "CStreamDataStanza::GetStreamId() error";

	default:
		return "CStreamDataStanza: Unknown error";
	}
}
