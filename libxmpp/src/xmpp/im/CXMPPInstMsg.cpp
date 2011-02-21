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
#include <vector>
#include <time.h>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/thread/CThread.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/core/CXMLFilter.h>
#include <xmpp/im/CRoster.h>
#include <xmpp/im/CRosterItem.h>
#include <xmpp/im/CXMPPInstMsg.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/iq/CIQStanza.h>
#include <xmpp/stanza/iq/error/CIQErrorStanza.h>
#include <xmpp/stanza/iq/get/CIQGetStanza.h>
#include <xmpp/stanza/iq/result/CIQResultStanza.h>
#include <xmpp/stanza/iq/set/CIQSetStanza.h>
#include <xmpp/stanza/message/CMessageStanza.h>
#include <xmpp/stanza/presence/CPresenceStanza.h>

using namespace std;

CXMPPInstMsg::CXMPPInstMsg() : CXMPPCore()
{
	CXMLFilter* pPresenceFilter = new CXMLFilter("presence");
	OnPresenceHandler.AddXMLFilter(pPresenceFilter);
}

CXMPPInstMsg::~CXMPPInstMsg()
{
}

bool CXMPPInstMsg::SendPresenceTo(const CJid* pJid, const string& show, const string& status, const string& priority)
{
	try
	{
		CPresenceStanza PresenceStanza;
		
		PresenceStanza.SetTo(pJid->GetFull());

		PresenceStanza.SetShow(show);
		PresenceStanza.SetStatus(status);
		PresenceStanza.SetPriority(priority);

		return Send(&PresenceStanza);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPInstMsgException(CXMPPInstMsgException::XMPPIMEC_SENDPRESENCETOERROR);
	}
}

bool CXMPPInstMsg::SendPresenceToAll(const string& show, const string& status, const string& priority)
{
	try
	{
		CPresenceStanza PresenceStanza;

		PresenceStanza.SetShow(show);
		PresenceStanza.SetStatus(status);
		PresenceStanza.SetPriority(priority);

		return Send(&PresenceStanza);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPInstMsgException(CXMPPInstMsgException::XMPPIMEC_SENDPRESENCETOALLERROR);
	}
}

void CXMPPInstMsg::StartRosterEvent(CRoster* pRoster)
{
	CIQStanza IQStanza;
	CHandler RosterHandler;
	CIQGetStanza IQGetStanza;
	string id;
	
	// we generate a unique id
	GenerateId(id);

	// we build the iq request
	IQGetStanza.SetId(id);
	
	CXMLNode* pXMLNode = new CXMLNode;
	pXMLNode->SetName("query");
	pXMLNode->SetNameSpace("jabber:iq:roster");

	IQGetStanza.PushChild(pXMLNode);

	// we build the filter handler adhoc
	CXMLFilter* pXMLFilter = new CXMLFilter("iq");
	pXMLFilter->SetAttribut("id", id);

	RosterHandler.AddXMLFilter(pXMLFilter);
	
	// we request the filter
	RequestHandler(&RosterHandler);
	
	if(!Send(&IQGetStanza))
	throw CXMPPInstMsgException(CXMPPInstMsgException::XMPPIMEC_UPDATEROSTERERROR);
	
	if(!Receive(&RosterHandler, &IQStanza))
	throw CXMPPInstMsgException(CXMPPInstMsgException::XMPPIMEC_UPDATEROSTERERROR);
	
	CommitHandler(&RosterHandler);
	RemoveId(id);
	
	if(IQStanza.GetKindOf() != CIQStanza::SIQKO_RESULT)
	throw CXMPPInstMsgException(CXMPPInstMsgException::XMPPIMEC_UPDATEROSTERERROR);
	
	CXMLNode* pQueryXMLNode =IQStanza.GetChild("query"); 

	for(u32 i = 0 ; i < pQueryXMLNode->GetNumChild() ; i++)
	{
		if(pQueryXMLNode->GetChild(i)->GetName() == "item")
		{
			CRosterItem RosterItem;
			RosterItem.SetJid(pQueryXMLNode->GetChild(i)->GetAttribut("jid"));
			pRoster->UpdateItem(RosterItem);
		}
	}

	RequestHandler(&OnPresenceHandler);
}

void CXMPPInstMsg::StopRosterEvent()
{
	CommitHandler(&OnPresenceHandler);
}


bool CXMPPInstMsg::OnRosterUpdated(CRoster* pRoster)
{
	CPresenceStanza PresenceStanza;

	if(!Receive(&OnPresenceHandler, &PresenceStanza))
	return false;
	
	CRosterItem RosterItem;

	RosterItem.SetJid(PresenceStanza.GetFrom());
	RosterItem.SetShow(PresenceStanza.GetShow());
	RosterItem.SetStatus(PresenceStanza.GetStatus());
	
	if(PresenceStanza.IsAvailable())
	RosterItem.SetAvailable();
	else
	RosterItem.SetUnavailable();
	
	pRoster->UpdateItem(RosterItem);
	return true;
}

CXMPPInstMsgException::CXMPPInstMsgException(int code) : CException(code)
{}

CXMPPInstMsgException::~CXMPPInstMsgException() throw()
{}
	
const char* CXMPPInstMsgException::what() const throw()
{
	switch(GetCode())
	{
	case XMPPIMEC_CONSTRUCTORERROR:
		return "CXMPPInstMsg::Constructor() error";
		
	case XMPPIMEC_DESTRUCTORERROR:
		return "CXMPPInstMsg::Destructor() error";
				
	case XMPPIMEC_SENDPRESENCETOERROR:
		return "CXMPPInstMsg::SendPresenceTo() error";
		
	case XMPPIMEC_SENDPRESENCETOALLERROR:
		return "CXMPPInstMsg::SendPresenceToAll() error";
		
	case XMPPIMEC_UPDATEROSTERERROR:
		return "CXMPPInstMsg::UpdateRoster() error";

	case XMPPIMEC_GETROSTERJIDERROR:
		return "CXMPPInstMsg::GetRosterJid() error";
		
	default:
		return "CXMPPInstMsg: Unknown error";
	}
}
