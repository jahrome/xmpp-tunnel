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
#include <common/xml/CXMLNode.h>

#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/stream/CFeaturesStanza.h>

using namespace std;

CFeaturesStanza::CFeaturesStanza() : CStanza()
{
	try
	{
		SetName("stream:features");
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CFeaturesStanzaException(CFeaturesStanzaException::FSEC_CONSTRUCTORERROR);
	}
}

CFeaturesStanza::~CFeaturesStanza()
{
}

CObject::u32 CFeaturesStanza::GetKindOf() const
{
	return SKO_FEATURES;
}

bool CFeaturesStanza::IsTLSRequired()
{
	try
	{
		if(!IsExistChild("starttls"))
		return false;
		
		CXMLNode* pStarttls = GetChild("starttls");
		
		if(pStarttls->GetNameSpace() != "urn:ietf:params:xml:ns:xmpp-tls")
		throw "error tls";
		
		return pStarttls->IsExistChild("required");
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CFeaturesStanzaException(CFeaturesStanzaException::FSEC_ISTLSREQUIREDERROR);
	}
}

CObject::u32 CFeaturesStanza::GetSASLMechanisms()
{
	try
	{
		u32 mechanisms = SASLM_NONE;

		if(!IsExistChild("mechanisms"))
		return SASLM_NONE;

		CXMLNode* pMechanisms = GetChild("mechanisms");
		
		if(pMechanisms->GetNameSpace() != "urn:ietf:params:xml:ns:xmpp-sasl")
		throw "error sasl";
		
		for(u32 i = 0 ; i < pMechanisms->GetNumChild() ; i++)
		{
			if(pMechanisms->GetChild(i)->GetName() != "mechanism")
			throw "error sasl";
			
			if(pMechanisms->GetChild(i)->GetData() == "X-GOOGLE-TOKEN")
			mechanisms |= SASLM_GOOGLE;

			if(pMechanisms->GetChild(i)->GetData() == "DIGEST-MD5")
			mechanisms |= SASLM_DIGEST;

			if(pMechanisms->GetChild(i)->GetData() == "PLAIN")
			mechanisms |= SASLM_PLAIN;
		}
		
		return mechanisms;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CFeaturesStanzaException(CFeaturesStanzaException::FSEC_GETSASLMECHANISMSERROR);
	}
}

bool CFeaturesStanza::IsBindRequired()
{
	try
	{
		if(!IsExistChild("bind"))
		return false;

		CXMLNode* pBind = GetChild("bind");
		
		if(pBind->GetNameSpace() != "urn:ietf:params:xml:ns:xmpp-bind")
		throw "error sasl";
		
		return true;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CFeaturesStanzaException(CFeaturesStanzaException::FSEC_ISBINDREQUIREDERROR);
	}
}

bool CFeaturesStanza::IsSessionRequired()
{
	try
	{
		if(!IsExistChild("session"))
		return false;

		CXMLNode* pSession = GetChild("session");
		
		if(pSession->GetNameSpace() != "urn:ietf:params:xml:ns:xmpp-session")
		throw "error session";
		
		return true;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CFeaturesStanzaException(CFeaturesStanzaException::FSEC_ISSESSIONREQUIREDERROR);
	}
}

CFeaturesStanzaException::CFeaturesStanzaException(int code) : CException(code)
{}

CFeaturesStanzaException::~CFeaturesStanzaException() throw()
{}


const char* CFeaturesStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case FSEC_CONSTRUCTORERROR:
		return "CFeaturesStanza::Constructor() error";
	
	case FSEC_ISTLSREQUIREDERROR:
		return "CFeaturesStanza::IsTLSRequired() Unknown error";

	case FSEC_GETSASLMECHANISMSERROR:
		return "CFeaturesStanza:GetSASLMechanisms() error";

	case FSEC_ISBINDREQUIREDERROR:
		return "CFeaturesStanza::IsBindRequired() error";

	case FSEC_ISSESSIONREQUIREDERROR:
		return "CFeaturesStanza::IsSessionRequired() error";

	default:
		return "CFeaturesStanza: Unknown error";
	}
}
