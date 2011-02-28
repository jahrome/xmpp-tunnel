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
 
#include <string>
#include <iostream>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBase64.h>
#include <common/data/CBuffer.h>
#include <common/socket/tcp/CTCPAddress.h>
#include <common/socket/tcp/tls/CTLSConnection.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/iq/CIQStanza.h>
#include <xmpp/stanza/iq/result/CIQResultStanza.h>
#include <xmpp/stanza/iq/set/CIQSetStanza.h>
#include <xmpp/stanza/iq/get/CIQGetStanza.h>
#include <xmpp/stanza/message/CMessageStanza.h>
#include <xmpp/stanza/presence/CPresenceStanza.h>
#include <xmpp/stanza/stream/CAuthStanza.h>
#include <xmpp/stanza/stream/CChallengeStanza.h>
#include <xmpp/stanza/stream/CCloseStanza.h>
#include <xmpp/stanza/stream/CFeaturesStanza.h>
#include <xmpp/stanza/stream/COpenStanza.h>
#include <xmpp/stanza/stream/CProceedStanza.h>
#include <xmpp/stanza/stream/CResponseStanza.h>
#include <xmpp/stanza/stream/CStarttlsStanza.h>
#include <xmpp/stanza/stream/CSuccessStanza.h>
#include <xmpp/core/CXMPPCore.h>
#include <xmpp/xml/CXMPPParser.h>

using namespace std;

CXMPPCore::CXMPPCore()
{
}

CXMPPCore::~CXMPPCore()
{
	try
	{
		if(IsConnected())
		Disconnect();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}
const CJid& CXMPPCore::GetJid() const
{
	return Jid;
}

void CXMPPCore::Connect(const CJid* pJid, const CTCPAddress* pTCPAddress)
{
	try
	{
		TCPAddress = pTCPAddress;
		Jid = pJid;

		TLSConnection.Connect(&TCPAddress);
		
		XMPPParser.ReInit();
		Negociate();
		
		MutexInQueue.ReInit();
		MutexOutQueue.ReInit();
		MutexHandlerList.ReInit();

		ThreadInJob.Run(&InJob, this);
		ThreadOutJob.Run(&OutJob, this);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_CONNECTERROR);
	}
}

void CXMPPCore::Disconnect()
{
	try
	{
		CCloseStanza CloseStanza;
		CBuffer Buffer;

		if(TLSConnection.IsConnected())
		{
			SendStanza(&CloseStanza);
			TLSConnection.Disconnect();
		}

		MutexInQueue.SignalDestroy();
		MutexOutQueue.SignalDestroy();

		ThreadInJob.Wait();
		ThreadOutJob.Wait();

		MutexHandlerList.Lock();

		for(u32 i = 0 ; i < HandlerList.size() ; i++)
		HandlerList[i]->SignalDestroy();

		HandlerList.clear();	

		MutexHandlerList.UnLock();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_DISCONNECTERROR);
	}
}

bool CXMPPCore::IsConnected() const
{
	return TLSConnection.IsConnected();
}

void* CXMPPCore::InJob(void* pvThis) throw()
{
	try
	{
		CXMPPCore* pThis = (CXMPPCore*) pvThis;

		while(pThis->IsConnected())
		{
			CStanza Stanza;

			if(!pThis->ReceiveStanza(&Stanza))
			return NULL;
			
			// If the stanza received is matching an existing handler
			// we push it into the queue in this handler
			pThis->MutexHandlerList.Lock();
			
			u32 i = 0;
			bool match = false;
			
			while(i < pThis->HandlerList.size())
			{
				if(pThis->HandlerList[i]->IsMatching(Stanza.GetXMLNode()))
				{
					match = true;
					CXMLNode* pXMLNode = new CXMLNode;
					pXMLNode->CopyFrom(Stanza.GetXMLNode());
					pThis->HandlerList[i]->PushXMLNode(pXMLNode);
				}

				i++;
			}
			
			pThis->MutexHandlerList.UnLock();
			
			// if the stanza does not match any handler we push it in the InQueue
			if(match == false)
			{
				pThis->MutexInQueue.Lock();

				pThis->InQueue.insert(pThis->InQueue.end(), Stanza.DetachXMLNode());
				
				pThis->MutexInQueue.Signal();
				
				pThis->MutexInQueue.UnLock();
			}
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

void* CXMPPCore::OutJob(void* pvThis) throw()
{
	try
	{
		CXMPPCore* pThis = (CXMPPCore*) pvThis;
		
		while(pThis->IsConnected())
		{
			CStanza Stanza;

			pThis->MutexOutQueue.Lock();
		
			while(pThis->OutQueue.empty())
			{
				if(!pThis->MutexOutQueue.Wait())
				{
					pThis->MutexOutQueue.UnLock();
					return NULL;
				}
			}
			
			Stanza.AttachXMLNode(pThis->OutQueue[0]);
			pThis->OutQueue.erase(pThis->OutQueue.begin() + 0);

			pThis->MutexOutQueue.UnLock();

			if(!pThis->SendStanza(&Stanza))
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

void CXMPPCore::RequestHandler(CHandler* pHandler)
{
	try
	{
		MutexHandlerList.Lock();
		HandlerList.insert(HandlerList.begin(), pHandler);
		MutexHandlerList.UnLock();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_REQUESTHANDLERERROR);	
	}
}

void CXMPPCore::CommitHandler(CHandler* pHandler)
{
	try
	{
		MutexHandlerList.Lock();

		for(u32 i = 0 ; i < HandlerList.size() ; i++)
		{
			if(HandlerList[i] == pHandler)
			HandlerList.erase(HandlerList.begin() + i);
		}

		pHandler->SignalDestroy();
		MutexHandlerList.UnLock();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_COMMITHANDLERERROR);	
	}
}

void CXMPPCore::GenerateId(string& id)
{
	try
	{
		MutexIDList.Lock();
		
		string randomId;
		srand(time(NULL));
		
		do
		{
			randomId = "XMPPSSH_";
			for(u8 i = 0 ; i < 10 ; i++)
			{
				int r = rand() % 36;
				(r < 26) ? randomId += (char) (r + 'A') : randomId += (char) (r - 26 + '0');
			}
		}while(IsIdExist(randomId));
		
		id = randomId;

		IDList.push_back(randomId);

		MutexIDList.UnLock();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_GENERATEIDERROR);	
	}
}

void CXMPPCore::RemoveId(const string& id)
{
	try
	{
		MutexIDList.Lock();
		
		for(u32 i = 0 ; i < IDList.size() ; i++)
		{
			if(IDList[i] == id)
			{
				IDList.erase(IDList.begin() + i);
				MutexIDList.UnLock();
				return;
			}
		}
	
		MutexIDList.UnLock();
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_REMOVEIDERROR);	
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_REMOVEIDERROR);	
	}
}

bool CXMPPCore::Receive(CStanza* pStanza)
{
	try
	{
		if(!IsConnected())
		return false;
	
		MutexInQueue.Lock();

		while(InQueue.empty())
		{
			if(!MutexInQueue.Wait())
			{
				MutexOutQueue.UnLock();
				return false;
			}
		}
		
		pStanza->AttachXMLNode(InQueue[0]);
		InQueue.erase(InQueue.begin() + 0);

		MutexInQueue.UnLock();
		
		return true;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_RECEIVEERROR);	
	}
}

bool CXMPPCore::Receive(CHandler* pHandler, CStanza* pStanza)
{
	try
	{
		if(!IsConnected())
		return false;
		
		CXMLNode* pXMLNode = pHandler->PopXMLNode();
		
		if(pXMLNode == NULL)
		return false;
		
		pStanza->AttachXMLNode(pXMLNode);
		return true;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_RECEIVEHANDLERERROR);	
	}
}

bool CXMPPCore::Send(CStanza* pStanza)
{
	try
	{
		if(!IsConnected())
		return false;

		MutexOutQueue.Lock();
	
		OutQueue.insert(OutQueue.end(), pStanza->DetachXMLNode());
		MutexOutQueue.Signal();

		MutexOutQueue.UnLock();
		
		return true;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_SENDERROR);	
	}
}

bool CXMPPCore::IsIdExist(const string& id)
{
	try
	{
		for(u32 i = 0 ; i < IDList.size() ; i++)
		{
			if(IDList[i] == id)
			return true;
		}
		
		return false;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_ISIDEXISTERROR);	
	}
}

bool CXMPPCore::SendStanza(const CStanza* pStanza)
{
	try
	{
		if(!IsConnected())
		return false;
	
		CBuffer Buffer;
		pStanza->Build(&Buffer);

		#ifdef __DEBUG__
		cout << "->[";
		for(u32 i = 0 ; i < Buffer.GetBufferSize() ; i++)
		cout << Buffer.GetBuffer()[i];
		cout << "]"<< endl;
		#endif //__DEBUG__
		
		if(!TLSConnection.Send(&Buffer))
		return false;

		return true;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_SENDSTANZAERROR);
	}
}

bool CXMPPCore::ReceiveStanza(CStanza* pStanza)
{
	try
	{
		if(!IsConnected())
		return false;

		while(XMPPParser.GetNumXMLNode() == 0)
		{
			CBuffer Buffer(1000);

			if(!TLSConnection.Receive(&Buffer))
			return false;

			#ifdef __DEBUG__
			cout << "<-[";			
			for(u32 i = 0 ; i < Buffer.GetBufferSize() ; i++)
			cout << Buffer.GetBuffer()[i];
			
			 cout << "]"<< endl;
			#endif //__DEBUG__
			
			XMPPParser.Write(&Buffer);
		}
	
		pStanza->AttachXMLNode(XMPPParser.GetXMLNode());
		return true;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_RECEIVESTANZAERROR);
	}
}

void CXMPPCore::Negociate()
{
	try
	{
		NegociateStarttls();
		NegociateSasl();
		NegociateBindSession();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATEERROR);
	}
}

void CXMPPCore::NegociateStarttls()
{
	try
	{
		CStanza Stanza;
		COpenStanza OpenStanza;
		CFeaturesStanza FeaturesStanza;
		CStarttlsStanza StarttlsStanza;

		// Sending stream:open
		OpenStanza.SetTo(Jid.GetHost());

		if(!SendStanza(&OpenStanza))
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESTARTTLSERROR);

		// Receiving stream:features
		if(!ReceiveStanza(&Stanza))
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESTARTTLSERROR);
		
		if(Stanza.GetKindOf() != CStanza::SKO_FEATURES)
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESTARTTLSERROR);

		FeaturesStanza.AttachXMLNode(Stanza.DetachXMLNode());

		SendStanza(&StarttlsStanza);
		ReceiveStanza(&Stanza);

		if(Stanza.GetKindOf() != CStanza::SKO_PROCEED)
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESTARTTLSERROR);
	
		XMPPParser.ReInit();
		TLSConnection.Secure();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESTARTTLSERROR);
	}
}
void CXMPPCore::NegociateSasl()
{
	try
	{
		CStanza Stanza;
		COpenStanza OpenStanza;
		CFeaturesStanza FeaturesStanza;
		CAuthStanza AuthStanza;

		// Sending stream:open
		OpenStanza.SetTo(Jid.GetHost());

		if(!SendStanza(&OpenStanza))
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);
		
		// Receiving stream:features
		if(!ReceiveStanza(&Stanza))
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);
		
		if(Stanza.GetKindOf() != CStanza::SKO_FEATURES)
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

		FeaturesStanza.AttachXMLNode(Stanza.DetachXMLNode());

		if(FeaturesStanza.GetSASLMechanisms() & CFeaturesStanza::SASLM_GOOGLE)
		{
			AuthStanza.SetMechanism(CAuthStanza::AM_GOOGLE, Jid);

			if(!SendStanza(&AuthStanza))
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

			if(!ReceiveStanza(&Stanza))
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);


			if(Stanza.GetKindOf() != CStanza::SKO_SUCCESS)
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);
	
			XMPPParser.ReInit();
			return;
		}

		if(FeaturesStanza.GetSASLMechanisms() & CFeaturesStanza::SASLM_DIGEST)
		{
			CAuthStanza Authtanza;
			CChallengeStanza ChallengeStanza1;
			CChallengeStanza ChallengeStanza2;
			CResponseStanza ResponseStanza1;
			CResponseStanza ResponseStanza2;
			
			AuthStanza.SetMechanism(CAuthStanza::AM_DIGEST, Jid);

			if(!SendStanza(&AuthStanza))
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

			if(!ReceiveStanza(&Stanza))
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

			if(Stanza.GetKindOf() != CStanza::SKO_CHALLENGE)
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);
	
			ChallengeStanza1.AttachXMLNode(Stanza.DetachXMLNode());
	
			string realm, nonce, qop, algorithm;
			
			ChallengeStanza1.GetValues(realm, nonce, qop, algorithm); 
			ResponseStanza1.SetValues(GetJid(), realm, nonce, qop, algorithm); 
	
			if(!SendStanza(&ResponseStanza1))
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

			if(!ReceiveStanza(&Stanza))
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

			if(Stanza.GetKindOf() != CStanza::SKO_CHALLENGE)
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);
			
			if(!SendStanza(&ResponseStanza2))
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

			if(!ReceiveStanza(&Stanza))
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

			if(Stanza.GetKindOf() != CStanza::SKO_SUCCESS)
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

			XMPPParser.ReInit();
			return;	
		}
		
		if(FeaturesStanza.GetSASLMechanisms() & CFeaturesStanza::SASLM_PLAIN)
		{
			CAuthStanza Authtanza;
			AuthStanza.SetMechanism(CAuthStanza::AM_PLAIN, Jid);

			if(!SendStanza(&AuthStanza))
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

			if(!ReceiveStanza(&Stanza))
			throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);

			XMPPParser.ReInit();
			return;
	
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESASLERROR);
	}

}

void CXMPPCore::NegociateBindSession()
{
	try
	{
		CStanza Stanza;
		COpenStanza OpenStanza;
		CFeaturesStanza FeaturesStanza;
		CAuthStanza AuthStanza;

		// Sending stream:open
		OpenStanza.SetTo(Jid.GetHost());

		if(!SendStanza(&OpenStanza))
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATEBINDSESSIONERROR);
		
		// Receiving stream:features
		ReceiveStanza(&Stanza);
		if(Stanza.GetKindOf() != CStanza::SKO_FEATURES)
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATEBINDSESSIONERROR);
		
		FeaturesStanza.AttachXMLNode(Stanza.DetachXMLNode());

		if(FeaturesStanza.IsBindRequired())
		NegociateBind();

		if(FeaturesStanza.IsSessionRequired())
		NegociateSession();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATEBINDSESSIONERROR);		
	}
}

void CXMPPCore::NegociateBind()
{
	try
	{
		CIQStanza IQStanza;
		CIQSetStanza IQSetStanza;
		
		IQSetStanza.SetTo(GetJid().GetFull());

		CXMLNode* pXMLNode = new CXMLNode;
		pXMLNode->SetName("bind");
		pXMLNode->SetNameSpace("urn:ietf:params:xml:ns:xmpp-bind");
		
		IQSetStanza.PushChild(pXMLNode);
		
		if(!SendStanza(&IQSetStanza))
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATEBINDERROR);
		
		if(!ReceiveStanza(&IQStanza))
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATEBINDERROR);
	
		if(IQStanza.GetKindOf() != CIQStanza::SIQKO_RESULT)
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATEBINDERROR);
		
		Jid.SetFull(IQStanza.GetChild("bind")->GetChild("jid")->GetData());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATEBINDERROR);		
	}

}

void CXMPPCore::NegociateSession()
{
	try
	{
		CIQStanza IQStanza;
		CIQSetStanza IQSetStanza;

		IQSetStanza.SetTo(GetJid().GetFull());

		CXMLNode* pXMLNode = new CXMLNode;
		pXMLNode->SetName("session");
		pXMLNode->SetNameSpace("urn:ietf:params:xml:ns:xmpp-session");
		IQSetStanza.PushChild(pXMLNode);
		
		if(!SendStanza(&IQSetStanza))
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESESSIONERROR);
		
		if(!ReceiveStanza(&IQStanza))
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESESSIONERROR);
	
		if(IQStanza.GetKindOf() != CIQStanza::SIQKO_RESULT)
		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESESSIONERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMPPCoreException(CXMPPCoreException::XMPPCEC_NEGOCIATESESSIONERROR);
	}
}

CXMPPCoreException::CXMPPCoreException(int code) : CException(code)
{}

CXMPPCoreException::~CXMPPCoreException() throw()
{}
	
const char* CXMPPCoreException::what() const throw()
{
	switch(GetCode())
	{
	case XMPPCEC_CONNECTERROR:
		return "CXMPPCore::Connect() error";

	case XMPPCEC_DISCONNECTERROR:
		return "CXMPPCore::Disconnect() error";

	case XMPPCEC_SENDSTANZAERROR:
		return "CXMPPCore::SendStanza() error";

	case XMPPCEC_RECEIVESTANZAERROR:
		return "CXMPPCore::ReceiveStanza() error";

	case XMPPCEC_RECEIVEERROR:
		return "CXMPPCore::Receive() error";
		
	case XMPPCEC_SENDERROR:
		return "CXMPPCore::Send() error";
		
	case XMPPCEC_REQUESTHANDLERERROR:
		return "CXMPPCore::RequestHandler() error";
		
	case XMPPCEC_RECEIVEHANDLERERROR:
		return "CXMPPCore::ReceiveHandler() error";
		
	case XMPPCEC_COMMITHANDLERERROR:
		return "CXMPPCore::CommitHandler() error";

	case XMPPCEC_GENERATEIDERROR:	
		return "CXMPPCore::GenerateUniqueId() error";	

	case XMPPCEC_REMOVEIDERROR:	
		return "CXMPPCore::RemoveId() error";	

	case XMPPCEC_ISIDEXISTERROR:
		return "CXMPPCore::IsIdExist() error";	

	case XMPPCEC_NEGOCIATEERROR:
		return "CXMPPCore::Negociate() error";

	case XMPPCEC_NEGOCIATESTARTTLSERROR:
		return "CXMPPCore::NegociateStarttls() error";

	case XMPPCEC_NEGOCIATESASLERROR:
		return "CXMPPCore::NegociateSasl() error";

	case XMPPCEC_NEGOCIATEBINDSESSIONERROR:
		return "CXMPPCore::NegociateBindSession() error";

	case XMPPCEC_NEGOCIATEBINDERROR:
		return "CXMPPCore::NegociateBind() error";

	case XMPPCEC_NEGOCIATESESSIONERROR:
		return "CXMPPCore::NegociateSession() error";

	default:
		return "CXMPPCore: Unknown error";
	}
}
