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
#include <string>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBase64.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/stream/CResponseStanza.h>

using namespace std;

CResponseStanza::CResponseStanza() : CStanza()
{
	try
	{
		SetName("response");
		SetNameSpace("urn:ietf:params:xml:ns:xmpp-sasl");
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CResponseStanzaException(CResponseStanzaException::RSEC_CONSTRUCTORERROR);
	}
}

CResponseStanza::~CResponseStanza()
{
}

CObject::u32 CResponseStanza::GetKindOf() const
{
	return SKO_RESPONSE;
}

void CResponseStanza::SetValues(const CJid& rJid, const string& realm, const string& nonce,
					const string& qop, const string& algorithm)
{
	try
	{
		string response, realmUsed, cnonce = "0123456789", rspauth, data;
		CBase64 Base64;
		
		if(realm.empty())
		realmUsed = rJid.GetHost();
		else
		realmUsed = realm;

		CBuffer Buffer, Token1(rJid.GetName().size() + realmUsed.size() + rJid.GetPassword().size() + 2);
		
		Token1.Write(rJid.GetName());
		Token1.Write((char)':');
		Token1.Write(realmUsed);
		Token1.Write((char)':');
		Token1.Write(rJid.GetPassword());
		
		u8 Token1Sum[16];

		Start();
		Append(&Token1);
		Finish(Token1Sum);

		CBuffer Token2(16 + nonce.size() + cnonce.size() + 2);
		Token2.Write(Token1Sum, 16);
		Token2.Write((char)':');
		Token2.Write(nonce);
		Token2.Write((char)':');
		Token2.Write(cnonce);
		
		u8 Token2Sum[16];
		Start();
		Append(&Token2);
		Finish(Token2Sum);

		CBuffer Token3(strlen("AUTHENTICATE:xmpp/") + realmUsed.size());
		Token3.Write("AUTHENTICATE:xmpp/");
		Token3.Write(realmUsed);
		
		u8 Token3Sum[16];
		Start();
		Append(&Token3);
		Finish(Token3Sum);

		u8 tok2[33];
		u8 tok3[33];
		
		ToHex(Token2Sum, tok2);
		ToHex(Token3Sum, tok3);
		
		CBuffer Token4(32 + nonce.size() + cnonce.size() + 8 + 4 + 32 + 5);
		Token4.Write(tok2, 32);
		Token4.Write((char)':');
		Token4.Write(nonce);
		Token4.Write((char)':');
		Token4.Write("00000001");
		Token4.Write((char)':');
		Token4.Write(cnonce);
		Token4.Write((char)':');
		Token4.Write("auth");
		Token4.Write((char)':');
		Token4.Write(tok3, 32);
		
		u8 Token4Sum[16];
		Start();
		Append(&Token4);
		Finish(Token4Sum);
		
		u8 tok4[33];
		ToHex(Token4Sum, tok4);
		rspauth.append((char*)tok4, 32);
		
		response = "username=\"" + rJid.GetName() + "\"";
		response += ",realm=\"" + realmUsed + "\"";
		response += ",nonce=\"" + nonce + "\"";
		response += ",cnonce=\"" + cnonce + "\"";
		response += ",nc=00000001";
		response += ",qop=" + qop;
		response += ",digest-uri=\"xmpp/" + realmUsed + "\"";
		response += ",response=" + rspauth;
		response += ",charset=utf-8";
		
		Buffer.Affect(response);
		Base64.To64(&Buffer, data);
		SetData(data.c_str(), data.size());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CResponseStanzaException(CResponseStanzaException::RSEC_SETVALUESERROR);
	}
}

void CResponseStanza::Start()
{
	MD5_Init(&ctx);
}

void CResponseStanza::Append(const CBuffer* pBuffer)
{
	MD5_Update(&ctx, pBuffer->GetBuffer(), pBuffer->GetBufferSize());
}

void CResponseStanza::Finish(u8* result)
{
	MD5_Final(result, &ctx);
}

void CResponseStanza::ToHex(u8* plain, u8* hex)
{
	for(int i = 0 ; i < 16 ; i++)
	sprintf((char*) (hex + (i * 2)), "%.2x", plain[i]);
}

CResponseStanzaException::CResponseStanzaException(int code) : CException(code)
{}

CResponseStanzaException::~CResponseStanzaException() throw()
{}

const char* CResponseStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case RSEC_CONSTRUCTORERROR:
		return "CResponseStanza:Constructor() error";

	case RSEC_SETVALUESERROR:
		return "CResponseStanza:SetValues() error";

	default:
		return "CResponseStanza: Unknown error";
	}
}
