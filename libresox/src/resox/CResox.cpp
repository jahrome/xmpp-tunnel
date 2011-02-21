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
#include <termios.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/crypto/rsa/CRsaKey.h>
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

CResox* pResox;
using namespace std;

CResox::CResox()
{
	pResox = this;
	//signal(SIGINT,   InterceptSignal);
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

void CResox::ConnectToSSH(const CJid& sshJid, CRsaKey* pAuthServerKey)
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
	
	XEPssh.ConnectToSSH(sshJid, pAuthServerKey);
}


void CResox::Login(const string& userName, const string& password)
{
	signal(SIGWINCH, InterceptSignal);

	XEPssh.Login(userName, password);

	termios old_tty;
	termios new_tty;

	tcgetattr(0, &old_tty);
	tcgetattr(0, &new_tty);
	
	new_tty.c_lflag &= ~(ICANON | ECHO);
	//new_tty.c_cc[VTIME] = 600 * 10;
	new_tty.c_cc[VMIN] = 1;

	tcsetattr(0, TCSANOW, &new_tty);

	try
	{
		// we send the current local shell size
		InterceptSignal(SIGWINCH);
		
		ThreadInShellJob.Run(InShellJob, this);
		ThreadOutShellJob.Run(OutShellJob, this);

		ThreadInShellJob.Wait();
		//ThreadOutShellJob.Wait();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}

	tcsetattr(0, TCSANOW, &old_tty);
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
	
	try
	{		
		CBuffer DataBuffer;

		while(true)
		{
			pResox->XEPssh.ReceiveData(&DataBuffer);
			u32 bufferSizeWrited = 0;

			while(DataBuffer.GetBufferSize() > bufferSizeWrited)
			{
				int currentSizeWrited = write(1, DataBuffer.GetBuffer() + bufferSizeWrited, DataBuffer.GetBufferSize() - bufferSizeWrited);
	
				if(currentSizeWrited < 0)
				{
					pResox->ThreadOutShellJob.Stop();
					pResox->XEPssh.Disconnect();
					return NULL;
				}
			
				bufferSizeWrited += currentSizeWrited;
			}

			fflush(stdout);
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
		
		while(read(0, DataBuffer.GetBuffer(), DataBuffer.GetBufferSize()) == 1)
		pResox->XEPssh.SendData(&DataBuffer);

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


void CResox::InterceptSignal(int signal)
{
	if(signal == SIGWINCH)
	{
		struct winsize w;
		if(ioctl(0, TIOCGWINSZ, &w) < 0)
		return;
		
		pResox->XEPssh.SetShellSize(w.ws_row, w.ws_col, w.ws_xpixel, w.ws_ypixel);
	}

	if(signal == SIGINT)
	{
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
