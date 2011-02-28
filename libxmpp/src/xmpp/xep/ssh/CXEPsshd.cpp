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

#include <vector>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>
#include <common/data/CBase64.h>
#include <common/thread/CMutex.h>
#include <common/thread/CThread.h>
#include <common/xml/CXMLNode.h>
#include <common/xml/CXMLParser.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/core/CXMLFilter.h>
#include <xmpp/core/CXMPPCore.h>
#include <xmpp/xep/ssh/CXEPsshd.h>

#include <xmpp/xep/ssh/node/CSessionShellDataNode.h>
#include <xmpp/xep/xibb/CXEPxibb.h>

using namespace std;


CXEPsshd::CXEPsshd()
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

		throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_CONSTRUCTORERROR);
	}
}

CXEPsshd::~CXEPsshd()
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


void CXEPsshd::Attach(CXMPPCore* pXMPPCore, int pTunFd)
{
	try
	{
		this->pXMPPCore = pXMPPCore;
		this->TunFd = pTunFd;
		XEPxibb.Attach(pXMPPCore);

		ThreadSessionManagerJob.Run(SessionManagerJob, this);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_ATTACHERROR);
	}
}

void CXEPsshd::Detach()
{
	try
	{
		if(pXMPPCore == NULL)
		return;
	
		XEPxibb.Detach();
		ThreadSessionManagerJob.Wait();
		
		pXMPPCore = NULL;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_DETACHERROR);
	}
}

void* CXEPsshd::SessionManagerJob(void* pvThis) throw()
{
	try
	{
		CXEPsshd* pXEPsshd = (CXEPsshd*) pvThis;
		int TunFd = pXEPsshd->TunFd;
		CXEPxibb* pXEPxibb = &pXEPsshd->XEPxibb;

		while(true)
		{
			u16 maxStream;
			u16 blockSize;
			u32 byteRate;

			SSessionParam* pSessionParam = new SSessionParam;

			pSessionParam->pXEPxibb = pXEPxibb;
			pSessionParam->TunFd = TunFd;

			pXEPxibb->WaitChannel(&pSessionParam->Jid, &pSessionParam->localCid, &maxStream, &blockSize, &byteRate);
			CThread::RunDetached(SessionJob, pSessionParam);
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		return NULL;
	}
}

void* CXEPsshd::SessionJob(void* pvSSessionParam) throw()
{
	SSessionParam* pSessionParam = (SSessionParam*) pvSSessionParam;
	
	try
	{
		SessionShell(pSessionParam);
		
		pSessionParam->pXEPxibb->CloseChannel(pSessionParam->Jid, pSessionParam->localCid);
		delete pSessionParam;
		return NULL;
	}
	
	catch(exception& e)
	{
		pSessionParam->pXEPxibb->CloseChannel(pSessionParam->Jid, pSessionParam->localCid);
		delete pSessionParam;
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		return NULL;
	}
}

void* CXEPsshd::InShellJob(void* pvSSessionParam) throw()
{
	SSessionParam* pSessionParam = (SSessionParam*) pvSSessionParam;
	CXEPxibb* pXEPxibb = pSessionParam->pXEPxibb;
	CJid Jid = pSessionParam->Jid;
	u16 localCid = pSessionParam->localCid;
	u16 shellSid = pSessionParam->shellSid;

	int TunFd = pSessionParam->TunFd;
	int nread;
	char buffer[2000];
	
	try
	{
		
		CBuffer DataBuffer;
		
		while(true)
		{
			CBase64 Base64;
			CBuffer Buffer, EncryptedBuffer, Data;
			CSessionShellDataNode SessionShellDataNode;
			
			pXEPxibb->ReceiveStreamData(Jid, localCid, shellSid, &Buffer);
			CXMLParser::Parse(&Buffer, &SessionShellDataNode);
			Base64.From64(SessionShellDataNode.GetData(), &Data);
			Data.Write(buffer);

			if (Data.GetBufferSize())
			{
				nread = write(TunFd, Data.GetBuffer(), Data.GetBufferSize());
				if(nread < 0) {
					perror("Write to interface");
					close(TunFd);
					exit(1);
				}
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

void* CXEPsshd::OutShellJob(void* pvSSessionParam) throw()
{	
	SSessionParam* pSessionParam = (SSessionParam*) pvSSessionParam;
	CXEPxibb* pXEPxibb = pSessionParam->pXEPxibb;
	CJid Jid = pSessionParam->Jid;
	u16 localCid = pSessionParam->localCid;
	u16 shellSid = pSessionParam->shellSid;
	int TunFd = pSessionParam->TunFd;
	int nread;
	char buffer[2000];

	try
	{
		while(true)
		{
			CBuffer Buffer, EncryptedBuffer, Data;
			string DataBase64;
			CBase64 Base64;
			CSessionShellDataNode SessionShellDataNode;

			nread = read(TunFd,buffer,sizeof(buffer));
			if(nread < 0) {
				perror("Reading from interface");
				close(TunFd);
				exit(1);
			}

			Data.Create((u32)nread);
			Data.Write((const u8*)buffer, (u32)nread);
			Base64.To64(&Data, DataBase64);
			SessionShellDataNode.SetData(DataBase64.c_str(), DataBase64.size());
			SessionShellDataNode.Build(&Buffer);

			pXEPxibb->SendStreamData(Jid, localCid, shellSid, &Buffer);
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


void CXEPsshd::SessionShell(SSessionParam* pSessionParam)
{
	try
	{
		CXEPxibb* pXEPxibb = pSessionParam->pXEPxibb;
		CJid Jid = pSessionParam->Jid;
		u16 localCid = pSessionParam->localCid;

		CThread ThreadInJob;
		CThread ThreadOutJob;
		u16 blockSize;
		u32 byteRate;

		pXEPxibb->WaitStream(Jid, localCid, &pSessionParam->shellSid, &blockSize, &byteRate);

		ThreadInJob.Run(InShellJob, pSessionParam);
		ThreadOutJob.Run(OutShellJob, pSessionParam);
		
		ThreadInJob.Wait();
		ThreadOutJob.Wait();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_SESSIONAUTHCLIENTERROR);
	}

}


CXEPsshdException::CXEPsshdException(int code) : CException(code)
{}

CXEPsshdException::~CXEPsshdException() throw()
{}
	
const char* CXEPsshdException::what() const throw()
{
	switch(GetCode())
	{
	case XEPSSHDEC_CONSTRUCTORERROR:
		return "CXEPsshd::Constructor() error";
		
	case XEPSSHDEC_DESTRUCTORERROR:
		return "CXEPsshd::Destructor() error";
		
	case XEPSSHDEC_ATTACHERROR:
		return "CXEPsshd::Attach() error";

	case XEPSSHDEC_DETACHERROR:
		return "CXEPsshd::Detach() error";
		
	case XEPSSHDEC_INSHELLJOBERROR:
		return "CXEPsshd::InShellJob() error";

	case XEPSSHDEC_OUTSHELLJOBERROR:
		return "CXEPsshd::OutShellJob() error";

	default:
		return "CXEPsshd: Unknown error";
	}
}
