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
#include <xmpp/stanza/stream/CChallengeStanza.h>

using namespace std;

CChallengeStanza::CChallengeStanza() : CStanza()
{
	try
	{
		SetName("challenge");
		SetNameSpace("urn:ietf:params:xml:ns:xmpp-sasl");
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChallengeStanzaException(CChallengeStanzaException::CSEC_CONSTRUCTORERROR);
	}
}

CChallengeStanza::~CChallengeStanza()
{
}

CObject::u32 CChallengeStanza::GetKindOf() const
{
	return SKO_CHALLENGE;
}

void CChallengeStanza::GetValues(string& realm, string& nonce, string& qop, string& algorithm) const
{
	try
	{
		CBase64 Base64;
		CBuffer Buffer;
		
		Base64.From64(GetData(), &Buffer);
		
		string str;
		str.append((char*) Buffer.GetBuffer(), Buffer.GetBufferSize());
		ExtractValue(str, "realm", realm);
		ExtractValue(str, "nonce", nonce);
		ExtractValue(str, "qop", qop);
		ExtractValue(str, "algorithm", algorithm);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChallengeStanzaException(CChallengeStanzaException::CSEC_GETVALUESERROR);
	}
}

void CChallengeStanza::ExtractValue(const string& str, const string& attribut, string& value) const
{
	try
	{
		u32 atPos = str.find(attribut,  0);

		if(atPos == string::npos)
		return;

		u32 startVal = atPos + attribut.size() + 1;
		u32 endVal = str.find(",", startVal + 1);

		if(endVal == string::npos)
		endVal = str.size();
		
		if(str[startVal] == '"')
		{
			startVal++;
			endVal--;
		}
		
		value = str.substr(startVal, endVal - startVal);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChallengeStanzaException(CChallengeStanzaException::CSEC_GETVALUESERROR);
	}

}


CChallengeStanzaException::CChallengeStanzaException(int code) : CException(code)
{}

CChallengeStanzaException::~CChallengeStanzaException() throw()
{}

const char* CChallengeStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case CSEC_CONSTRUCTORERROR:
		return "CChallengeStanza:Constructor() error";

	case CSEC_GETVALUESERROR:
		return "CChallengeStanza:GetValues() error";

	default:
		return "CChallengeStanza: Unknown error";
	}
}
