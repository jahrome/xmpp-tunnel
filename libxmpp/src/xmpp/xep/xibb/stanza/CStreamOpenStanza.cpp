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
#include <xmpp/xep/xibb/stanza/CStreamOpenStanza.h>

using namespace std;

CStreamOpenStanza::CStreamOpenStanza()
{
}

CStreamOpenStanza::CStreamOpenStanza(const CJid& rRemoteJid, u16 channelId, u16 streamId, u16 blockSize, u32 byteRate, const string& id)
{
	try
	{
		Init(rRemoteJid, channelId, streamId, blockSize, byteRate, id);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamOpenStanzaException(CStreamOpenStanzaException::SOSEC_CONSTRUCTORERROR);
	}
}

void CStreamOpenStanza::Init(const CJid& rRemoteJid, u16 channelId, u16 streamId, u16 blockSize, u32 byteRate, const string& id)
{
	try
	{
		// we convert cid and sid to a string
		ostringstream CidConvertor;
		ostringstream SidConvertor;
		ostringstream BlockSizeConvertor;
		ostringstream ByteRateConvertor;
		
		CidConvertor << channelId;
		SidConvertor << streamId;
		BlockSizeConvertor << blockSize;
		ByteRateConvertor << byteRate;
	
		SetTo(rRemoteJid.GetFull());
		SetId(id);

		
		CXMLNode* pSubNode;
		
		if(!IsExistChild("stream-open"))
		{
			pSubNode = new CXMLNode("stream-open");
			PushChild(pSubNode);
		}
		else
		pSubNode = GetChild("stream-open");
		
		
		pSubNode->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");
		pSubNode->SetAttribut("cid", CidConvertor.str());
		pSubNode->SetAttribut("sid", SidConvertor.str());
		pSubNode->SetAttribut("block-size", BlockSizeConvertor.str());
		pSubNode->SetAttribut("byte-rate", ByteRateConvertor.str());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamOpenStanzaException(CStreamOpenStanzaException::SOSEC_INITERROR);
	}
}

CStreamOpenStanza::~CStreamOpenStanza()
{
}

const string& CStreamOpenStanza::GetRemoteJid() const
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

		throw CStreamOpenStanzaException(CStreamOpenStanzaException::SOSEC_GETREMOTEJIDERROR);
	}
}

CObject::u16 CStreamOpenStanza::GetChannelId() const
{
	try
	{
		istringstream CidConvertor(GetChild("stream-open")->GetAttribut("cid"));
		u16 channelId;
		
		CidConvertor >> channelId;
		
		return channelId;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamOpenStanzaException(CStreamOpenStanzaException::SOSEC_GETCHANNELIDERROR);
	}
}

CObject::u16 CStreamOpenStanza::GetStreamId() const
{
	try
	{
		istringstream SidConvertor(GetChild("stream-open")->GetAttribut("sid"));
		u16 streamId;
		
		SidConvertor >> streamId;
		
		return streamId;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamOpenStanzaException(CStreamOpenStanzaException::SOSEC_GETSTREAMIDERROR);
	}
}

CObject::u16 CStreamOpenStanza::GetBlockSize() const
{
	try
	{
		istringstream BlockSizeConvertor(GetChild("stream-open")->GetAttribut("block-size"));
		u16 blockSize;
		
		BlockSizeConvertor >> blockSize;
		
		return blockSize;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamOpenStanzaException(CStreamOpenStanzaException::SOSEC_GETBLOCKSIZEERROR);
	}
}
CObject::u32 CStreamOpenStanza::GetByteRate() const
{
	try
	{
		istringstream ByteRateConvertor(GetChild("stream-open")->GetAttribut("byte-rate"));
		u32 byteRate;
		
		ByteRateConvertor >> byteRate;
		
		return byteRate;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CStreamOpenStanzaException(CStreamOpenStanzaException::SOSEC_GETBYTERATEERROR);
	}
}


CStreamOpenStanzaException::CStreamOpenStanzaException(int code) : CException(code)
{}

CStreamOpenStanzaException::~CStreamOpenStanzaException() throw()
{}
	
const char* CStreamOpenStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case SOSEC_CONSTRUCTORERROR:
		return "CStreamOpenStanza::Constructor() error";
						
	case SOSEC_INITERROR:
		return "CStreamOpenStanza::Init() error";

	case SOSEC_GETREMOTEJIDERROR:
		return "CStreamOpenStanza::GetRemoteJid() error";

	case SOSEC_GETCHANNELIDERROR:
		return "CStreamOpenStanza::GetChannelId() error";

	case SOSEC_GETSTREAMIDERROR:
		return "CStreamOpenStanza::GetStreamId() error";

	case SOSEC_GETBLOCKSIZEERROR:
		return "CStreamOpenStanza::GetBlockSize() error";

	case SOSEC_GETBYTERATEERROR:
		return "CStreamOpenStanza::GetByteRate() error";

	default:
		return "CStreamOpenStanza: Unknown error";
	}
}
