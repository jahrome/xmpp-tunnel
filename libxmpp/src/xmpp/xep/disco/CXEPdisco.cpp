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

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/core/CXMLFilter.h>
#include <xmpp/core/CHandler.h>
#include <xmpp/core/CXMPPCore.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/iq/get/CIQGetStanza.h>
#include <xmpp/stanza/iq/result/CIQResultStanza.h>
#include <xmpp/xep/disco/CXEPdisco.h>

using namespace std;

CXEPdisco::CXEPdisco()
{
	try
	{
		pXMPPCore = NULL;
		
		// we build the disco handler
		CXMLFilter* pDiscoFilter = new CXMLFilter("iq");
		pDiscoFilter->SetAttribut("type", "get");

		CXMLFilter* pQueryFilter = new CXMLFilter("query");
		pQueryFilter->SetAttribut("xmlns", "http://jabber.org/protocol/disco#info");

		pDiscoFilter->PushChild(pQueryFilter);

		DiscoHandler.AddXMLFilter(pDiscoFilter);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPdiscoException(CXEPdiscoException::XEPDEC_CONSTRUCTORERROR);
	}
}

CXEPdisco::~CXEPdisco()
{
	try
	{
		if(pXMPPCore != NULL)
		Detach();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

void CXEPdisco::Attach(CXMPPCore* pXMPPCore)
{
	try
	{
		this->pXMPPCore = pXMPPCore;
		pXMPPCore->RequestHandler(&DiscoHandler);
		ThreadOnDisco.Run(OnDiscoJob, this);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPdiscoException(CXEPdiscoException::XEPDEC_ATTACHERROR);
	}
}
	
void CXEPdisco::Detach()
{
	try
	{
		if(pXMPPCore == NULL)
		return;
	
		pXMPPCore->CommitHandler(&DiscoHandler);
		ThreadOnDisco.Wait();
		pXMPPCore = NULL;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPdiscoException(CXEPdiscoException::XEPDEC_DETACHERROR);
	}
}


void CXEPdisco::Disco(vector<string>* pFeaturesList)
{
	Disco(pXMPPCore->GetJid().GetHost(), pFeaturesList);
}

void CXEPdisco::Disco(const CJid& rJid, vector<string>* pFeaturesList)
{
	try
	{
		CHandler Handler;
		CIQGetStanza IQGetStanza;
		CIQResultStanza IQResultStanza;
		string id;
		
		pXMPPCore->GenerateId(id);
		
		//we build and request the disco filter
		CXMLFilter* pXMLFilter = new CXMLFilter("iq");
		pXMLFilter->SetAttribut("id", id);
		pXMLFilter->SetAttribut("type", "result");
		pXMLFilter->SetAttribut("from", rJid.GetFull());
		
		Handler.AddXMLFilter(pXMLFilter);
		
		pXMPPCore->RequestHandler(&Handler);
		
		// we build the disco query request
		IQGetStanza.SetTo(rJid.GetFull());
		IQGetStanza.SetId(id);
		
		CXMLNode* pXMLNode = new CXMLNode("query");
		pXMLNode->SetNameSpace("http://jabber.org/protocol/disco#info");

		IQGetStanza.PushChild(pXMLNode);

		if(!pXMPPCore->Send(&IQGetStanza))
		throw CXEPdiscoException(CXEPdiscoException::XEPDEC_DISCOERROR);
		
		if(!pXMPPCore->Receive(&Handler, &IQResultStanza))
		throw CXEPdiscoException(CXEPdiscoException::XEPDEC_DISCOERROR);

		pXMPPCore->CommitHandler(&Handler);
		pXMPPCore->RemoveId(id);
				
		pFeaturesList->clear();
		CXMLNode* pResultQuery = IQResultStanza.GetChild("query");

		for(u32 i = 0 ; i < pResultQuery->GetNumChild() ; i++)
		{
			if(pResultQuery->GetChild(i)->GetName() == "feature")
			pFeaturesList->push_back(pResultQuery->GetChild(i)->GetAttribut("var"));
		}
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPdiscoException(CXEPdiscoException::XEPDEC_DISCOERROR);
	}
}

void* CXEPdisco::OnDiscoJob(void* pvThis) throw()
{
	try
	{	
		CXEPdisco* pXEPdisco = (CXEPdisco*) pvThis;
		CIQGetStanza IQGetStanza;

		while(pXEPdisco->pXMPPCore->Receive(&pXEPdisco->DiscoHandler, &IQGetStanza))
		{
			CIQResultStanza IQResultStanza;
			
			IQResultStanza.SetTo(IQGetStanza.GetFrom());
			IQResultStanza.SetId(IQGetStanza.GetId());
			
			CXMLNode* pQueryNode = new CXMLNode("query");
			CXMLNode* pFeatureDiscoNode = new CXMLNode("feature");
			CXMLNode* pFeatureResoxNode = new CXMLNode("feature");
			
			pQueryNode->SetAttribut("xmlns", "http://jabber.org/protocol/disco#info");
			pFeatureDiscoNode->SetAttribut("var", "http://jabber.org/protocol/disco#info");
			pFeatureResoxNode->SetAttribut("var", "http://jabber.org/protocol/xibb");
			pFeatureResoxNode->SetAttribut("var", "http://jabber.org/protocol/xmpp-ssh");

			pQueryNode->PushChild(pFeatureDiscoNode);
			pQueryNode->PushChild(pFeatureResoxNode);
			IQResultStanza.PushChild(pQueryNode);

		
			if(!pXEPdisco->pXMPPCore->Send(&IQResultStanza))
			return NULL;
		}
		
		return NULL;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		return NULL;
	}
}


CXEPdiscoException::CXEPdiscoException(int code) : CException(code)
{}

CXEPdiscoException::~CXEPdiscoException() throw()
{}
	
const char* CXEPdiscoException::what() const throw()
{
	switch(GetCode())
	{
	case XEPDEC_CONSTRUCTORERROR:
		return "CXEPdisco::Constructor() error";
		
	case XEPDEC_DESTRUCTORERROR:
		return "CXEPdisco::Destructor() error";
		
	case XEPDEC_DISCOERROR:
		return "CXEPdisco::Disco() error";
		
	case XEPDEC_ONDISCOERROR:
		return "CXEPdisco::OnDisco() error";
		
	case XEPDEC_ATTACHERROR:
		return "CXEPdisco::Attach() error";

	case XEPDEC_DETACHERROR:
		return "CXEPdisco::Detach() error";

	default:
		return "CXEPdisco: Unknown error";
	}
}
