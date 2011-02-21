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

#ifndef __CXMPPCORE_H__
#define __CXMPPCORE_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/socket/tcp/CTCPAddress.h>
#include <common/socket/tcp/tls/CTLSConnection.h>
#include <common/thread/CThread.h>
#include <common/xml/CXMLNode.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/iq/CIQStanza.h>
#include <xmpp/xml/CXMPPParser.h>

using namespace std;

class CXMPPCore : public CObject
{
public:
	CXMPPCore();
	virtual ~CXMPPCore();

	void Connect(const CJid* pJid, const CTCPAddress* pTCPAddress);
	void Disconnect();
	
	bool IsConnected() const;

	bool Send(CStanza* pStanza);
	bool Receive(CStanza* pStanza);
	bool Receive(CHandler* pHandler, CStanza* pStanza);

	const CJid& GetJid() const;

	void RequestHandler(CHandler* pHandler);
	void CommitHandler(CHandler* pHandler);

	void GenerateId(string& id);
	void RemoveId(const string& id);

protected:
	bool SendStanza(const CStanza* pStanza);
	bool ReceiveStanza(CStanza* pStanza);
	
private:
	void Negociate();
	
	void NegociateStarttls();
	void NegociateSasl();
	void NegociateBindSession();
	void NegociateBind();
	void NegociateSession();

	static void* InJob(void* pvThis) throw();
	static void* OutJob(void* pvThis) throw();
	
	bool IsIdExist(const string& id);
	
private:
	CJid Jid;
	CTCPAddress TCPAddress;
	CXMPPParser XMPPParser;
	CTLSConnection TLSConnection;
	
	vector<CHandler*> HandlerList;
	vector<string> IDList;
	vector<CXMLNode*> InQueue;
	vector<CXMLNode*> OutQueue;
	CMutex MutexHandlerList;
	CMutex MutexIDList;
	CMutex MutexInQueue;
	CMutex MutexOutQueue;
	CThread ThreadInJob;
	CThread ThreadOutJob;
};
 
class CXMPPCoreException : public CException
{
public:
	enum XMPPCoreExceptionCode
	{
		XMPPCEC_CONNECTERROR,
		XMPPCEC_DISCONNECTERROR,
		XMPPCEC_RECEIVEERROR,
		XMPPCEC_SENDERROR,
		XMPPCEC_REQUESTHANDLERERROR,
		XMPPCEC_RECEIVEHANDLERERROR,	
		XMPPCEC_COMMITHANDLERERROR,
		XMPPCEC_GENERATEIDERROR,
		XMPPCEC_REMOVEIDERROR,
		XMPPCEC_ISIDEXISTERROR,
		XMPPCEC_SENDSTANZAERROR,
		XMPPCEC_RECEIVESTANZAERROR,
		XMPPCEC_NEGOCIATEERROR,
		XMPPCEC_NEGOCIATESTARTTLSERROR,
		XMPPCEC_NEGOCIATESASLERROR,
		XMPPCEC_NEGOCIATEBINDSESSIONERROR,
		XMPPCEC_NEGOCIATEBINDERROR,
		XMPPCEC_NEGOCIATESESSIONERROR
	};

public:
	CXMPPCoreException(int code);
	virtual ~CXMPPCoreException() throw();

	virtual const char* what() const throw();
};

#endif // __CXMPPCORE_H__
