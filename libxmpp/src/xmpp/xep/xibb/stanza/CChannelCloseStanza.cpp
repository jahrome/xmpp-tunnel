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
#include <xmpp/xep/xibb/stanza/CChannelCloseStanza.h>

using namespace std;

CChannelCloseStanza::CChannelCloseStanza()
{
}

CChannelCloseStanza::CChannelCloseStanza(const CJid& rRemoteJid, u16 channelId, const string& id)
{
	try
	{
		Init(rRemoteJid, channelId, id);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelCloseStanzaException(CChannelCloseStanzaException::CCSEC_CONSTRUCTORERROR);
	}
}

void CChannelCloseStanza::Init(const CJid& rRemoteJid, u16 channelId, const string& id)
{
	try
	{
		// we convert cid to a string
		ostringstream CidConvertor;
		CidConvertor << channelId;
	
		SetTo(rRemoteJid.GetFull());
		SetId(id);

		CXMLNode* pSubNode;

		if(!IsExistChild("channel-close"))
		{
			pSubNode = new CXMLNode("channel-close");
			PushChild(pSubNode);
		}
		else
		pSubNode = GetChild("channel-close");
		
		pSubNode->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");
		pSubNode->SetAttribut("cid", CidConvertor.str());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelCloseStanzaException(CChannelCloseStanzaException::CCSEC_INITERROR);
	}
}

CChannelCloseStanza::~CChannelCloseStanza()
{
}

const string& CChannelCloseStanza::GetRemoteJid() const
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

		throw CChannelCloseStanzaException(CChannelCloseStanzaException::CCSEC_GETREMOTEJIDERROR);
	}
}

CObject::u16 CChannelCloseStanza::GetChannelId() const
{
	try
	{
		istringstream CidConvertor(GetChild("channel-close")->GetAttribut("cid"));
		u16 channelId;
		
		CidConvertor >> channelId;
		
		return channelId;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelCloseStanzaException(CChannelCloseStanzaException::CCSEC_GETCHANNELIDERROR);
	}
}

CChannelCloseStanzaException::CChannelCloseStanzaException(int code) : CException(code)
{}

CChannelCloseStanzaException::~CChannelCloseStanzaException() throw()
{}
	
const char* CChannelCloseStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case CCSEC_CONSTRUCTORERROR:
		return "CChannelCloseStanza::Constructor() error";
						
	case CCSEC_INITERROR:
		return "CChannelCloseStanza::Init() error";

	case CCSEC_GETREMOTEJIDERROR:
		return "CChannelCloseStanza::GetRemoteJid() error";

	case CCSEC_GETCHANNELIDERROR:
		return "CChannelCloseStanza::GetChannelId() error";

	default:
		return "CChannelCloseStanza: Unknown error";
	}
}
