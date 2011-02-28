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
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/socket/tcp/CTCPAddress.h>
#include <common/thread/CThread.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/core/CXMLFilter.h>
#include <xmpp/im/CRoster.h>
#include <xmpp/im/CRosterItem.h>
#include <xmpp/im/CXMPPInstMsg.h>
#include <xmpp/jid/CJid.h>
#include <xmpp/stanza/CStanza.h>
#include <xmpp/stanza/presence/CPresenceStanza.h>
#include <xmpp/stanza/iq/get/CIQGetStanza.h>
#include <xmpp/stanza/iq/result/CIQResultStanza.h>
#include <xmpp/xep/disco/CXEPdisco.h>

#include <resox/CResox.h>

#include <common/tun/tun.h>


CResox* pResox;
using namespace std;

CResox::CResox()
{
}

CResox::CResox(const string pAddress, const string pMask)
{
	char tun_name[] = "xmpp0";

	pResox = this;

	/* Connect to the device */
	tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
	set_ip(tun_name, pAddress.c_str(), pMask.c_str());

	if(tun_fd < 0){
		perror("Allocating interface");
		exit(0);
	}
	cerr << "Created local network interface " << tun_name << endl;
}

CResox::~CResox()
{
	XEPdisco.Detach();
	XEPssh.Detach();
	XMPPInstMsg.Disconnect();
}

void CResox::ConnectTo(const CJid& xmppJid, const CTCPAddress& rTCPAddress)
{
	XMPPInstMsg.Connect(&xmppJid, &rTCPAddress);
	XMPPInstMsg.SendPresenceToAll("available", "", "0");
}

void CResox::ConnectToSSH(const CJid& sshJid)
{
	XEPdisco.Attach(&XMPPInstMsg);
	XEPssh.Attach(&XMPPInstMsg);

	vector<string> FeaturesList;
	XEPdisco.Disco(sshJid, &FeaturesList);

	bool isResoxFeature = false;

	for(u32 i = 0 ; i < FeaturesList.size() ; i++)
	{
		if(FeaturesList[i] == "http://jabber.org/protocol/xmpp-ssh")
		isResoxFeature = true;
	}

	if(!isResoxFeature)
	cerr << sshJid.GetFull() << " may not support xmpp-ssh " << endl;
	
	XEPssh.ConnectToSSH(sshJid);
}


void CResox::Login()
{
	XEPssh.Login();

	cerr << "Tunnel established" << endl;

	try
	{
		ThreadInShellJob.Run(InShellJob, this);
		ThreadOutShellJob.Run(OutShellJob, this);

		ThreadInShellJob.Wait();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

void CResox::StartRosterEvent(CRoster* pRoster)
{
	 XMPPInstMsg.StartRosterEvent(pRoster);
}


void CResox::StopRosterEvent()
{
	 XMPPInstMsg.StopRosterEvent();	
}

bool CResox::OnRosterUpdated(CRoster* pRoster)
{
	return XMPPInstMsg.OnRosterUpdated(pRoster);
}

void* CResox::InShellJob(void* pvThis) throw()
{
	CResox* pResox = (CResox*) pvThis;
	int nread;

	try
	{		
		CBuffer DataBuffer;

		while(true)
		{
			pResox->XEPssh.ReceiveData(&DataBuffer);
			nread = write(pResox->tun_fd, DataBuffer.GetBuffer(), DataBuffer.GetBufferSize());
			if(nread < 0) {
				perror("Write to interface");
				close(pResox->tun_fd);
				exit(1);
			}
		}
	}
	
	catch(exception& e)
	{
		pResox->ThreadOutShellJob.Stop();
		pResox->XEPssh.Disconnect();
		return NULL;
	}
}

void* CResox::OutShellJob(void* pvThis) throw()
{
	CResox* pResox = (CResox*) pvThis;
	
	try
	{	
		CBuffer DataBuffer(1);
		
		char buffer[2000];
		int nread;

		while ((nread = read(pResox->tun_fd,buffer,sizeof(buffer)))) {
			if(nread < 0) {
				perror("Reading from interface");
				close(pResox->tun_fd);
				exit(1);
			}
			DataBuffer.Create((u32)nread);
			DataBuffer.Write((const u8*)buffer, (u32)nread);
			pResox->XEPssh.SendData(&DataBuffer);
		}

		pResox->ThreadInShellJob.Stop();
		pResox->XEPssh.Disconnect();
		return NULL;
	}
	
	catch(exception& e)
	{
		pResox->ThreadInShellJob.Stop();
		pResox->XEPssh.Disconnect();
		return NULL;
	}
}

CResoxException::CResoxException(int code) : CException(code)
{}

CResoxException::~CResoxException() throw()
{}

const char* CResoxException::what() const throw()
{
	switch(GetCode())
	{
	case REC_RUNERROR:
		return "CResox::Run() error";
	
	default:
		return "CResox: Unknown error";
	}
}
