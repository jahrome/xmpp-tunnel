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
#include <sstream>
#include <string>

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBase64.h>
#include <common/thread/CMutex.h>
#include <common/thread/CThread.h>
#include <common/xml/CXMLNode.h>
#include <common/xml/CXMLParser.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/core/CXMLFilter.h>
#include <xmpp/core/CXMPPCore.h>
#include <xmpp/xep/ssh/CXEPssh.h>
#include <xmpp/xep/ssh/node/CSessionShellDataNode.h>
#include <xmpp/xep/xibb/CXEPxibb.h>

using namespace std;

CXEPssh::CXEPssh()
{
	try
	{
		pXMPPCore = NULL;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshException(CXEPsshException::XEPSSHEC_CONSTRUCTORERROR);
	}
}

CXEPssh::~CXEPssh()
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

void CXEPssh::Attach(CXMPPCore* pXMPPCore)
{
	try
	{
		this->pXMPPCore = pXMPPCore;
		XEPxibb.Attach(pXMPPCore);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshException(CXEPsshException::XEPSSHEC_ATTACHERROR);
	}
}

void CXEPssh::Detach()
{
	try
	{
		if(pXMPPCore == NULL)
		return;
	
		XEPxibb.Detach();
	
		pXMPPCore = NULL;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshException(CXEPsshException::XEPSSHEC_DETACHERROR);
	}
}

void CXEPssh::ConnectToSSH(const CJid& rRemoteJid)
{
	try
	{
		RemoteJid = rRemoteJid;
		
		XEPxibb.OpenChannel(RemoteJid, &channelId);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshException(CXEPsshException::XEPSSHEC_CONNECTTOSSHERROR); 
	}
}

void CXEPssh::Disconnect()
{
	try
	{
		XEPxibb.CloseChannel(RemoteJid, channelId);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshException(CXEPsshException::XEPSSHEC_DISCONNECTERROR); 
	}
}


const CJid& CXEPssh::GetRemoteJid() const
{
	return RemoteJid;
}


void CXEPssh::SendData(CBuffer* pBuffer)
{
	try
	{
		CBase64 Base64;
		CBuffer Buffer, EncryptedBuffer;
		string DataBase64;
		CSessionShellDataNode SessionShellDataNode;
	
		Base64.To64(pBuffer, DataBase64);
		SessionShellDataNode.SetData(DataBase64.c_str(), DataBase64.size());

		SessionShellDataNode.Build(&Buffer);
		XEPxibb.SendStreamData(RemoteJid, channelId, shellSid, &Buffer);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshException(CXEPsshException::XEPSSHEC_SENDDATAERROR);
	}
}

void CXEPssh::ReceiveData(CBuffer* pBuffer)
{
	try
	{
		CBase64 Base64;
		CBuffer Buffer, EncryptedBuffer;
		CSessionShellDataNode SessionShellDataNode;

		XEPxibb.ReceiveStreamData(RemoteJid, channelId, shellSid, &Buffer);

		CXMLParser::Parse(&Buffer, &SessionShellDataNode);
		Base64.From64(SessionShellDataNode.GetData(), pBuffer);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshException(CXEPsshException::XEPSSHEC_RECEIVEDATAERROR);
	}
}


void CXEPssh::Login()
{
	try
	{
		XEPxibb.OpenStream(RemoteJid, channelId, &shellSid);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshException(CXEPsshException::XEPSSHEC_SESSIONAUTHCLIENTERROR);
	}
}

CXEPsshException::CXEPsshException(int code) : CException(code)
{}

CXEPsshException::~CXEPsshException() throw()
{}
	
const char* CXEPsshException::what() const throw()
{
	switch(GetCode())
	{
	case XEPSSHEC_CONSTRUCTORERROR:
		return "CXEPssh::Constructor() error";
		
	case XEPSSHEC_DESTRUCTORERROR:
		return "CXEPssh::Destructor() error";
		
	case XEPSSHEC_ATTACHERROR:
		return "CXEPssh::Attach() error";

	case XEPSSHEC_CONNECTTOSSHERROR:
		return "CXEPssh::ConnectTo() error";

	case XEPSSHEC_DISCONNECTERROR:
		return "CXEPssh::Disconnect() error";

	case XEPSSHEC_DETACHERROR:
		return "CXEPssh::Detach() error";
	
	case XEPSSHEC_SENDDATAERROR:
		return "CXEPssh::SendData() error";

	case XEPSSHEC_RECEIVEDATAERROR:
		return "CXEPssh::ReceiveData() error";

	case XEPSSHEC_SETSHELLSIZEERROR:
		return "CXEPssh::SetShellSize() error";

	case XEPSSHEC_SESSIONAUTHCLIENTERROR:
		return "CXEPssh::SessionAuthClient() error";

	default:
		return "CXEPssh: Unknown error";
	}
}
