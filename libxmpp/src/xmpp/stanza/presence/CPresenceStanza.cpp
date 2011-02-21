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
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/presence/CPresenceStanza.h>

using namespace std;

CPresenceStanza::CPresenceStanza() : CStanza()
{
	try
	{
		SetName("presence");
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CPresenceStanzaException(CPresenceStanzaException::PSEC_CONSTRUCTORERROR);
	}
}

CPresenceStanza::~CPresenceStanza()
{
}

CObject::u32 CPresenceStanza::GetKindOf() const
{
	return SKO_PRESENCE;
}

void CPresenceStanza::SetShow(const string& show)
{
	try
	{
		if(show.empty())
		return;

		if(!IsExistChild("show"))
		{
			CXMLNode* pShow = new CXMLNode;
			pShow->SetName("show");
			PushChild(pShow);
		}
		
		GetChild("show")->SetData(show.c_str(), show.size());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CPresenceStanzaException(CPresenceStanzaException::PSEC_SETSHOWERROR);
	}
}

void CPresenceStanza::SetStatus(const string& status)
{
	try
	{
		if(status.empty())
		return;
		
		if(!IsExistChild("status"))
		{
			CXMLNode* pStatus = new CXMLNode;
			pStatus->SetName("status");
			PushChild(pStatus);
		}
		
		GetChild("status")->SetData(status.c_str(), status.size());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CPresenceStanzaException(CPresenceStanzaException::PSEC_SETSTATUSERROR);
	}
}

void CPresenceStanza::SetPriority(const string& priority)
{
	try
	{
		if(priority.empty())
		return;

		if(!IsExistChild("priority"))
		{
			CXMLNode* pPriority = new CXMLNode;
			pPriority->SetName("priority");
			PushChild(pPriority);
		}
		
		GetChild("priority")->SetData(priority.c_str(), priority.size());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CPresenceStanzaException(CPresenceStanzaException::PSEC_SETPRIORITYERROR);
	}
}

const string& CPresenceStanza::GetShow() const
{
	if(!IsExistChild("show"))
	return CONST_STRING_EMPTY;

	return GetChild("show")->GetData();
}

const string& CPresenceStanza::GetStatus() const
{
	if(!IsExistChild("status"))
	return CONST_STRING_EMPTY;

	return GetChild("status")->GetData();
}

const string& CPresenceStanza::GetPriority() const
{
	if(!IsExistChild("priority"))
	return CONST_STRING_EMPTY;

	return GetChild("priority")->GetData();
}

bool CPresenceStanza::IsAvailable() const
{
	if(!IsExistAttribut("type"))
	return true;

	return GetAttribut("type") != "unavailable";
}

CPresenceStanzaException::CPresenceStanzaException(int code) : CException(code)
{}

CPresenceStanzaException::~CPresenceStanzaException() throw()
{}

const char* CPresenceStanzaException::what() const throw()
{
	switch(GetCode())
	{
	case PSEC_CONSTRUCTORERROR:
		return "CPresenceStanza::Constructor() error";

	case PSEC_SETSHOWERROR:
		return "CPresenceStanza::SetShow() error";

	case PSEC_SETSTATUSERROR:
		return "CPresenceStanza::SetStatus() error";

	case PSEC_SETPRIORITYERROR:
		return "CPresenceStanza::SetPriority() error";

	default:
		return "CPresenceStanza: Unknown error";
	}
}
