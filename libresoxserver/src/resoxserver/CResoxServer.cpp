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

#include <common/CObject.h>
#include <common/CException.h>
#include <common/crypto/rsa/CRsa.h>
#include <common/crypto/rsa/CRsaKey.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/im/CXMPPInstMsg.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/iq/get/CIQGetStanza.h>
#include <xmpp/stanza/iq/result/CIQResultStanza.h>
#include <xmpp/xep/disco/CXEPdisco.h>
#include <xmpp/xep/ssh/CXEPsshd.h>

#include <resoxserver/CResoxServer.h>

using namespace std;

CResoxServer::CResoxServer()
{
	try
	{
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CResoxServerException(CResoxServerException::RSEC_RUNERROR);
	}

}

CResoxServer::~CResoxServer()
{
}

void CResoxServer::Run(const CJid* pJid, const CTCPAddress* pTCPAddress, CRsaKey& rRsaServerKey)
{
	try
	{
		CStanza Stanza;
		vector<string> FeaturesList;
				
		XEPsshd.SetServerAuthKey(&rRsaServerKey);
		
		cout << "connecting to xmpp server ... " << flush;
		XMPPInstMsg.Connect(pJid, pTCPAddress);
		cout << "done" << endl;

		XEPdisco.Attach(&XMPPInstMsg);
		XEPsshd.Attach(&XMPPInstMsg);

		// we signal to the server that we are managing the disco protocol
		XEPdisco.Disco(&FeaturesList);

		// the resox server is now available
		XMPPInstMsg.SendPresenceToAll("available", "remote shell over xmpp - server", "0");
		cout << "sshd on " << XMPPInstMsg.GetJid().GetFull() << " is ready." << endl;
		
		while(XMPPInstMsg.Receive(&Stanza))
		{
			// we drop all unhandled stanza
		}

		XEPsshd.Detach();
		XEPdisco.Detach();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CResoxServerException(CResoxServerException::RSEC_RUNERROR);
	}
}

CResoxServerException::CResoxServerException(int code) : CException(code)
{}

CResoxServerException::~CResoxServerException() throw()
{}

const char* CResoxServerException::what() const throw()
{
	switch(GetCode())
	{
	case RSEC_RUNERROR:
		return "CResoxServer::Run() error";

	case RSEC_PROCESSSTANZAERROR:
		return "CResoxServer::ProcessStanza() error";
	
	default:
		return "CResoxServer: Unknown error";
	}
}
