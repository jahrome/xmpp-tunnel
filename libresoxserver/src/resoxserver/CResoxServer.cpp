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

#include <xmpp/core/CHandler.h>
#include <xmpp/im/CXMPPInstMsg.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/iq/get/CIQGetStanza.h>
#include <xmpp/stanza/iq/result/CIQResultStanza.h>
#include <xmpp/xep/disco/CXEPdisco.h>
#include <xmpp/xep/ssh/CXEPsshd.h>
#include <xmpp/stanza/CStanza.h>

#include <resoxserver/CResoxServer.h>

#include <common/tun/tun.h>

using namespace std;

CResoxServer::CResoxServer()
{
}

CResoxServer::CResoxServer(const string pAddress, const string pMask)
{
	try
	{
		char tun_name[] = "xmppd0";
		/* Connect to the device */
		TunFd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
		set_ip(tun_name, pAddress.c_str(), pMask.c_str());

		if(TunFd < 0){
			perror("Allocating interface");
			exit(0);
		}
		cerr << "Created local network interface " << tun_name << endl;
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

void* presense_thread(void* pvThis) throw()
{
	CResoxServer* me = (CResoxServer*) pvThis;
	for (int i=0 ; i<3 ; i++)
	{
		me->XMPPInstMsg.SendPresenceToAll("available", "Hi! I'm here", "0");
		sleep(5);
	}
}

void* keepalive_thread(void* pvThis) throw()
{
	CResoxServer* me = (CResoxServer*) pvThis;
	vector<string> FeaturesList;
	try
	{
	while(true)
	{
		// This is a hack to check for disconnection
		me->XEPdisco.Disco(&FeaturesList);
		sleep(300);
	}
	}
	catch(exception& e)
	{
			cerr << "Disconnected !" << endl;
			exit(0);
	}
}

void CResoxServer::Run(const CJid* pJid, const CTCPAddress* pTCPAddress)
{
	try
	{
		CStanza Stanza;
		vector<string> FeaturesList;
				
		cout << "connecting to xmpp server ... " << flush;
		XMPPInstMsg.Connect(pJid, pTCPAddress);
		cout << "done" << endl;

		XEPdisco.Attach(&XMPPInstMsg);
		XEPsshd.Attach(&XMPPInstMsg, TunFd);

		// we signal to the server that we are managing the disco protocol
		XEPdisco.Disco(&FeaturesList);

		// the resox server is now available
		XMPPInstMsg.SendPresenceToAll("available", "remote shell over xmpp - server init", "0");
		cout << "sshd on " << XMPPInstMsg.GetJid().GetFull() << " is ready." << endl;
		
		CThread Presence;
		CThread KeepAlive;
		KeepAlive.Run(keepalive_thread, this);

		while(XMPPInstMsg.Receive(&Stanza))
		{
			// This was needed to appear online on client connection on some servers
			// need to investigate more on this issue
			if (Stanza.GetKindOf() == CStanza::SKO_PRESENCE 
				&& Stanza.GetFrom().find(pJid->GetShort()) == string::npos)
			{
				cout << "New friend :" << Stanza.GetFrom() << endl;
				Presence.Run(presense_thread, this);
				Presence.Wait();
			} else {
				cout << "Got my packet :" << Stanza.GetFrom() << endl;
			}
		}
		KeepAlive.Wait();

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
