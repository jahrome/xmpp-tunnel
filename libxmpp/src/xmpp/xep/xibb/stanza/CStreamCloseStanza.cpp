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
#include <xmpp/stanza/iq/set/CIQSetStanza.h>
#include <xmpp/xep/xibb/stanza/CStreamCloseStanza.h>

using namespace std;

CStreamCloseStanza::CStreamCloseStanza()
{
}

CStreamCloseStanza::CStreamCloseStanza(const CJid& rRemoteJid, u16 channelId, u16 streamId, const string& id)
{
	try
	{
		Init(rRemoteJid, channelId, streamId, id);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamCloseStanzaException(CStreamCloseStanzaException::SCSEC_CONSTRUCTORERROR);
	}
}

void CStreamCloseStanza::Init(const CJid& rRemoteJid, u16 channelId, u16 streamId, const string& id)
{
	try
	{
		// we convert cid and sid to a string
		ostringstream CidConvertor;
		ostringstream SidConvertor;
		
		CidConvertor << channelId;
		SidConvertor << streamId;
	
		SetTo(rRemoteJid.GetFull());
		SetId(id);

		
		CXMLNode* pSubNode;
		
		if(!IsExistChild("stream-close"))
		{
			pSubNode = new CXMLNode("stream-close");
			PushChild(pSubNode);
		}
		else
		pSubNode = GetChild("stream-close");
		
		
		pSubNode->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");
		pSubNode->SetAttribut("cid", CidConvertor.str());
		pSubNode->SetAttribut("sid", SidConvertor.str());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamCloseStanzaException(CStreamCloseStanzaException::SCSEC_INITERROR);
	}
}

CStreamCloseStanza::~CStreamCloseStanza()
{
}

const string& CStreamCloseStanza::GetRemoteJid() const
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

		throw CStreamCloseStanzaException(CStreamCloseStanzaException::SCSEC_GETREMOTEJIDERROR);
	}
}

CObject::u16 CStreamCloseStanza::GetChannelId() const
{
	try
	{
		istringstream CidConvertor(GetChild("stream-close")->GetAttribut("cid"));
		u16 channelId;
		
		CidConvertor >> channelId;
		
		return channelId;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamCloseStanzaException(CStreamCloseStanzaException::SCSEC_GETCHANNELIDERROR);
	}
}

CObject::u16 CStreamCloseStanza::GetStreamId() const
{
	try
	{
		istringstream SidConvertor(GetChild("stream-close")->GetAttribut("sid"));
		u16 streamId;
		
		SidConvertor >> streamId;
		
		return streamId;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamCloseStanzaException(CStreamCloseStanzaException::SCSEC_GETSTREAMIDERROR);
	}
}

CStreamCloseStanzaException::CStreamCloseStanzaException(int code) : CException(code)
{}

CStreamCloseStanzaException::~CStreamCloseStanzaException() throw()
{}
	
const char* CStreamCloseStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case SCSEC_CONSTRUCTORERROR:
		return "CStreamCloseStanza::Constructor() error";
						
	case SCSEC_INITERROR:
		return "CStreamCloseStanza::Init() error";

	case SCSEC_GETREMOTEJIDERROR:
		return "CStreamCloseStanza::GetRemoteJid() error";

	case SCSEC_GETCHANNELIDERROR:
		return "CStreamCloseStanza::GetChannelId() error";

	case SCSEC_GETSTREAMIDERROR:
		return "CStreamCloseStanza::GetStreamId() error";

	default:
		return "CStreamCloseStanza: Unknown error";
	}
}
