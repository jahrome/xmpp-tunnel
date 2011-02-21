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
#include <xmpp/xep/xibb/stanza/CChannelOpenStanza.h>

using namespace std;

CChannelOpenStanza::CChannelOpenStanza()
{
}

CChannelOpenStanza::CChannelOpenStanza(const CJid& rRemoteJid, u16 channelId, u16 maxStream, u16 blockSize, u32 byteRate, const string& id)
{
	try
	{
		Init(rRemoteJid, channelId, maxStream, blockSize, byteRate, id);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelOpenStanzaException(CChannelOpenStanzaException::COSEC_CONSTRUCTORERROR);
	}
}

void CChannelOpenStanza::Init(const CJid& rRemoteJid, u16 channelId, u16 maxStream, u16 blockSize, u32 byteRate, const string& id)
{
	try
	{
		// we convert cid to a string
		ostringstream CidConvertor;
		ostringstream MaxStreamConvertor;
		ostringstream BlockSizeConvertor;
		ostringstream ByteRateConvertor;
		
		CidConvertor << channelId;
		MaxStreamConvertor << maxStream;
		BlockSizeConvertor << blockSize;
		ByteRateConvertor << byteRate;
	
		SetTo(rRemoteJid.GetFull());
		SetId(id);

		CXMLNode* pSubNode;

		if(!IsExistChild("channel-open"))
		{
			pSubNode = new CXMLNode("channel-open");
			PushChild(pSubNode);
		}
		else
		pSubNode = GetChild("channel-open");
		
		pSubNode->SetAttribut("xmlns", "http://jabber.org/protocol/xibb");
		pSubNode->SetAttribut("cid", CidConvertor.str());
		pSubNode->SetAttribut("max-stream", MaxStreamConvertor.str());
		pSubNode->SetAttribut("block-size", BlockSizeConvertor.str());
		pSubNode->SetAttribut("byte-rate", ByteRateConvertor.str());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelOpenStanzaException(CChannelOpenStanzaException::COSEC_INITERROR);
	}
}

CChannelOpenStanza::~CChannelOpenStanza()
{
}

const string& CChannelOpenStanza::GetRemoteJid() const
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

		throw CChannelOpenStanzaException(CChannelOpenStanzaException::COSEC_GETREMOTEJIDERROR);
	}
}

CObject::u16 CChannelOpenStanza::GetChannelId() const
{
	try
	{
		istringstream CidConvertor(GetChild("channel-open")->GetAttribut("cid"));
		u16 channelId;
		
		CidConvertor >> channelId;
		
		return channelId;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelOpenStanzaException(CChannelOpenStanzaException::COSEC_GETCHANNELIDERROR);
	}
}

CObject::u16 CChannelOpenStanza::GetMaxStream() const
{
	try
	{
		istringstream MaxStreamConvertor(GetChild("channel-open")->GetAttribut("max-stream"));
		u16 maxStream;
		
		MaxStreamConvertor >> maxStream;
		
		return maxStream;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelOpenStanzaException(CChannelOpenStanzaException::COSEC_GETMAXSTREAMERROR);
	}
}

CObject::u16 CChannelOpenStanza::GetBlockSize() const
{
	try
	{
		istringstream MaxStreamConvertor(GetChild("channel-open")->GetAttribut("block-size"));
		u16 blockSize;
		
		MaxStreamConvertor >> blockSize;
		
		return blockSize;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelOpenStanzaException(CChannelOpenStanzaException::COSEC_GETBLOCKSIZEERROR);
	}
}

CObject::u32 CChannelOpenStanza::GetByteRate() const
{
	try
	{
		istringstream ByteRateConvertor(GetChild("channel-open")->GetAttribut("byte-rate"));
		u32 byteRate;
		
		ByteRateConvertor >> byteRate;
		
		return byteRate;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelOpenStanzaException(CChannelOpenStanzaException::COSEC_GETBYTERATEERROR);
	}
}

CChannelOpenStanzaException::CChannelOpenStanzaException(int code) : CException(code)
{}

CChannelOpenStanzaException::~CChannelOpenStanzaException() throw()
{}
	
const char* CChannelOpenStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case COSEC_CONSTRUCTORERROR:
		return "CChannelOpenStanza::Constructor() error";
						
	case COSEC_INITERROR:
		return "CChannelOpenStanza::Init() error";

	case COSEC_GETREMOTEJIDERROR:
		return "CChannelOpenStanza::GetRemoteJid() error";

	case COSEC_GETCHANNELIDERROR:
		return "CChannelOpenStanza::GetChannelId() error";

	case COSEC_GETMAXSTREAMERROR:
		return "CChannelOpenStanza::GetMaxStream() error";

	case COSEC_GETBLOCKSIZEERROR:
		return "CChannelOpenStanza::GetBlockSize() error";

	case COSEC_GETBYTERATEERROR:
		return "CChannelOpenStanza::GetByteRate() error";

	default:
		return "CChannelOpenStanza: Unknown error";
	}
}
