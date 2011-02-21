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
#include <common/crypto/aes/CAes.h>
#include <common/crypto/rsa/CRsa.h>
#include <common/crypto/rsa/CRsaKey.h>
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

#include <xmpp/xep/ssh/auth/CAuthentication.h>
#include <xmpp/xep/ssh/node/CSessionAuthServerFeaturesGetNode.h>
#include <xmpp/xep/ssh/node/CSessionAuthServerFeaturesResultNode.h>
#include <xmpp/xep/ssh/node/CSessionAuthServerStartNode.h>
#include <xmpp/xep/ssh/node/CSessionAuthServerDoneNode.h>
#include <xmpp/xep/ssh/node/CSessionAuthClientFeaturesGetNode.h>
#include <xmpp/xep/ssh/node/CSessionAuthClientFeaturesResultNode.h>
#include <xmpp/xep/ssh/node/CSessionAuthClientStartNode.h>
#include <xmpp/xep/ssh/node/CSessionAuthClientDoneNode.h>
#include <xmpp/xep/ssh/node/CSessionKeyExchangeFeaturesGetNode.h>
#include <xmpp/xep/ssh/node/CSessionKeyExchangeFeaturesResultNode.h>
#include <xmpp/xep/ssh/node/CSessionKeyExchangeDoNode.h>
#include <xmpp/xep/ssh/node/CSessionKeyExchangeDoneNode.h>
#include <xmpp/xep/ssh/node/CSessionKeyExchangeStartNode.h>
#include <xmpp/xep/ssh/node/CSessionShellDataNode.h>
#include <xmpp/xep/ssh/virtualshell/CVirtualShell.h>
#include <xmpp/xep/xibb/CXEPxibb.h>

using namespace std;

CXEPsshd::CXEPsshd()
{
	try
	{
		pXMPPCore = NULL;
		pServerAuthKey = NULL;
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

void CXEPsshd::SetServerAuthKey(CRsaKey* pServerAuthKey)
{
	try
	{
		this->pServerAuthKey = pServerAuthKey;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_SETSERVERAUTHKEYERROR);
	}
}

void CXEPsshd::Attach(CXMPPCore* pXMPPCore)
{
	try
	{
		this->pXMPPCore = pXMPPCore;
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
		CXEPxibb* pXEPxibb = &pXEPsshd->XEPxibb;

		while(true)
		{
			u16 maxStream;
			u16 blockSize;
			u32 byteRate;

			SSessionParam* pSessionParam = new SSessionParam;

			pSessionParam->pXEPxibb = pXEPxibb;
			pSessionParam->pServerAuthKey = pXEPsshd->pServerAuthKey;

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
		SessionKeyExchange(pSessionParam);
		SessionAuthServer(pSessionParam);
		SessionAuthClient(pSessionParam);
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
	
	try
	{
		pSessionParam = (SSessionParam*) pvSSessionParam;
		pXEPxibb = pSessionParam->pXEPxibb;
		Jid = pSessionParam->Jid;
		localCid = pSessionParam->localCid;
		shellSid = pSessionParam->shellSid;
		
		CBuffer DataBuffer;
		
		while(true)
		{
			CBase64 Base64;
			CBuffer Buffer, EncryptedBuffer, Data;
			CSessionShellDataNode SessionShellDataNode;
			
			pXEPxibb->ReceiveStreamData(Jid, localCid, shellSid, &EncryptedBuffer);
			pSessionParam->AesOnShell.Decrypt(EncryptedBuffer, &Buffer);
			CXMLParser::Parse(&Buffer, &SessionShellDataNode);
			Base64.From64(SessionShellDataNode.GetData(), &Data);
			
			if(!pSessionParam->VirtualShell.Write(&Data))
			{
				pXEPxibb->CloseStream(Jid, localCid, shellSid);
				throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_OUTSHELLJOBERROR);
			}
			
			if(SessionShellDataNode.IsWindowChanged())
			{
				int row    = SessionShellDataNode.GetRow();
				int col    = SessionShellDataNode.GetColumn();
				int xpixel = SessionShellDataNode.GetX();
				int ypixel = SessionShellDataNode.GetY();
				
				pSessionParam->VirtualShell.SetShellSize(row, col, xpixel, ypixel);
			}
		}
		
		return NULL;
	}
	
	catch(exception& e)
	{
		pSessionParam->VirtualShell.Destroy();
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
	
	try
	{
		while(true)
		{
			CBuffer Buffer, EncryptedBuffer, Data;
			string DataBase64;
			CBase64 Base64;
			CSessionShellDataNode SessionShellDataNode;

			if(!pSessionParam->VirtualShell.Read(&Data))
			{
				pXEPxibb->CloseStream(Jid, localCid, shellSid);
				throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_OUTSHELLJOBERROR);
			}
			
			Base64.To64(&Data, DataBase64);
			SessionShellDataNode.SetData(DataBase64.c_str(), DataBase64.size());

			SessionShellDataNode.Build(&Buffer);
			pSessionParam->AesOnShell.Encrypt(Buffer, &EncryptedBuffer);
			pXEPxibb->SendStreamData(Jid, localCid, shellSid, &EncryptedBuffer);
		}

		return NULL;
	}
	
	catch(exception& e)
	{
		pSessionParam->VirtualShell.Destroy();
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		return NULL;
	}
}

void CXEPsshd::SessionKeyExchange(SSessionParam* pSessionParam)
{
	try
	{		
		CXEPxibb* pXEPxibb = pSessionParam->pXEPxibb;
		CJid Jid = pSessionParam->Jid;
		u16 localCid = pSessionParam->localCid;

		CBuffer Buffer;
		CSessionKeyExchangeFeaturesGetNode SessionKeyExchangeFeaturesGetNode;
		CSessionKeyExchangeFeaturesResultNode SessionKeyExchangeFeaturesResultNode;
		CSessionKeyExchangeStartNode SessionKeyExchangeStartNode;
		CSessionKeyExchangeDoNode SessionKeyExchangeDoNode;
		CSessionKeyExchangeDoneNode SessionKeyExchangeDoneNode;

		// we answere the keyexchange features request
		pXEPxibb->ReceiveChannelData(Jid, localCid, &Buffer);
		CXMLParser::Parse(&Buffer, &SessionKeyExchangeFeaturesGetNode);
		
		SessionKeyExchangeFeaturesResultNode.Build(&Buffer);
		pXEPxibb->SendChannelData(Jid, localCid, &Buffer);

		// we negociate the shared key
		pXEPxibb->ReceiveChannelData(Jid, localCid, &Buffer);
		CXMLParser::Parse(&Buffer, &SessionKeyExchangeStartNode);

		CRsaKey RsaKey;
		CBuffer PlainKey1, PlainKey2, EncryptedKey2, SessionKey;
		
		RsaKey.GenerateKey(1024, 3);
		CRsa::GenerateChallenge(32, &PlainKey1);

		SessionKeyExchangeDoNode.SetPublicKey(RsaKey);
		SessionKeyExchangeDoNode.SetPlainKey1(PlainKey1);

		SessionKeyExchangeDoNode.Build(&Buffer);
		pXEPxibb->SendChannelData(Jid, localCid, &Buffer);

		pXEPxibb->ReceiveChannelData(Jid, localCid, &Buffer);
		CXMLParser::Parse(&Buffer, &SessionKeyExchangeDoneNode);
		
		SessionKeyExchangeDoneNode.GetEncryptedKey2(&EncryptedKey2);
		
		CRsa::DecryptChallenge(RsaKey, EncryptedKey2, &PlainKey2);
		
		SessionKey.Create(32);
		
		for(u8 i = 0 ; i < SessionKey.GetBufferSize() ; i++)
		SessionKey.Write((u8) (PlainKey1.GetBuffer()[i] ^ PlainKey2.GetBuffer()[i]));

		pSessionParam->AesOnChannel.SetKey(SessionKey);
		pSessionParam->AesOnShell.SetKey(SessionKey);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_SESSIONKEYEXCHANGEERROR);
	}
}

void CXEPsshd::SessionAuthServer(SSessionParam* pSessionParam)
{
	try
	{
		CXEPxibb* pXEPxibb = pSessionParam->pXEPxibb;
		CJid Jid = pSessionParam->Jid;
		u16 localCid = pSessionParam->localCid;
		CRsaKey* pServerAuthKey = pSessionParam->pServerAuthKey;

		CBuffer DataBuffer, EncryptedDataBuffer;

		CSessionAuthServerFeaturesGetNode SessionAuthServerFeaturesGetNode;
		CSessionAuthServerFeaturesResultNode SessionAuthServerFeaturesResultNode;
		CSessionAuthServerStartNode SessionAuthServerStartNode;
		CSessionAuthServerDoneNode SessionAuthServerDoneNode;

		// we answere the auth server features request
		pXEPxibb->ReceiveChannelData(Jid, localCid, &EncryptedDataBuffer);
		pSessionParam->AesOnChannel.Decrypt(EncryptedDataBuffer, &DataBuffer);
		CXMLParser::Parse(&DataBuffer, &SessionAuthServerFeaturesGetNode);
		
		SessionAuthServerFeaturesResultNode.SetPublicKey(*pServerAuthKey);
		
		SessionAuthServerFeaturesResultNode.Build(&DataBuffer);
		pSessionParam->AesOnChannel.Encrypt(DataBuffer, &EncryptedDataBuffer);
		pXEPxibb->SendChannelData(Jid, localCid, &EncryptedDataBuffer);

		// we proof to the client that we have the private key associates
		// to the public key which has been used to encrypt the challenge
		pXEPxibb->ReceiveChannelData(Jid, localCid, &EncryptedDataBuffer);
		pSessionParam->AesOnChannel.Decrypt(EncryptedDataBuffer, &DataBuffer);
		CXMLParser::Parse(&DataBuffer, &SessionAuthServerStartNode);

		CBuffer Challenge, Signature;
		SessionAuthServerStartNode.GetChallenge(&Challenge);
		CRsa::SignChallenge(*pServerAuthKey, Challenge, &Signature);
		SessionAuthServerDoneNode.SetSignature(Signature);
				
		SessionAuthServerDoneNode.Build(&DataBuffer);
		pSessionParam->AesOnChannel.Encrypt(DataBuffer, &EncryptedDataBuffer);
		pXEPxibb->SendChannelData(Jid, localCid, &EncryptedDataBuffer);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_SESSIONAUTHSERVERERROR);
	}
}

void CXEPsshd::SessionAuthClient(SSessionParam* pSessionParam)
{
	try
	{
		CXEPxibb* pXEPxibb = pSessionParam->pXEPxibb;
		CJid Jid = pSessionParam->Jid;
		u16 localCid = pSessionParam->localCid;

		CBuffer DataBuffer, EncryptedDataBuffer;

		CSessionAuthClientFeaturesGetNode SessionAuthClientFeaturesGetNode;
		CSessionAuthClientFeaturesResultNode SessionAuthClientFeaturesResultNode;
		CSessionAuthClientStartNode SessionAuthClientStartNode;
		CSessionAuthClientDoneNode SessionAuthClientDoneNode;

		// we answere the auth client features request
		pXEPxibb->ReceiveChannelData(Jid, localCid, &EncryptedDataBuffer);
		pSessionParam->AesOnChannel.Decrypt(EncryptedDataBuffer, &DataBuffer);
		CXMLParser::Parse(&DataBuffer, &SessionAuthClientFeaturesGetNode);
		
		SessionAuthClientFeaturesResultNode.Build(&DataBuffer);
		pSessionParam->AesOnChannel.Encrypt(DataBuffer, &EncryptedDataBuffer);
		pXEPxibb->SendChannelData(Jid, localCid, &EncryptedDataBuffer);

		// we proof to the client that we have the private key associates
		// to the public key which has been used to encrypt the challenge
		pXEPxibb->ReceiveChannelData(Jid, localCid, &EncryptedDataBuffer);
		pSessionParam->AesOnChannel.Decrypt(EncryptedDataBuffer, &DataBuffer);
		CXMLParser::Parse(&DataBuffer, &SessionAuthClientStartNode);

		string userName = SessionAuthClientStartNode.GetUserName();
		string password = SessionAuthClientStartNode.GetPassword();

		if(!pSessionParam->Authentication.Authenticate(userName, password))
		throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_SESSIONAUTHCLIENTERROR);		
		// AuthClient
	
		SessionAuthClientDoneNode.Build(&DataBuffer);
		pSessionParam->AesOnChannel.Encrypt(DataBuffer, &EncryptedDataBuffer);
		pXEPxibb->SendChannelData(Jid, localCid, &EncryptedDataBuffer);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshdException(CXEPsshdException::XEPSSHDEC_SESSIONAUTHCLIENTERROR);
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

		pSessionParam->VirtualShell.Create(pSessionParam->Authentication.GetUID(),
											pSessionParam->Authentication.GetGID(),
											pSessionParam->Authentication.GetShell(),
											pSessionParam->Authentication.GetHomePath());
		
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
		
	case XEPSSHDEC_SETSERVERAUTHKEYERROR:
		return "CXEPsshd::SetServerAuthKey() error";

	case XEPSSHDEC_ATTACHERROR:
		return "CXEPsshd::Attach() error";

	case XEPSSHDEC_DETACHERROR:
		return "CXEPsshd::Detach() error";
		
	case XEPSSHDEC_SESSIONKEYEXCHANGEERROR:
		return "CXEPsshd::SessionKeyExchange() error";

	case XEPSSHDEC_SESSIONAUTHSERVERERROR:
		return "CXEPsshd::SessionAuthServer() error";

	case XEPSSHDEC_SESSIONAUTHCLIENTERROR:
		return "CXEPsshd::SessionAuthClient() error";

	case XEPSSHDEC_INSHELLJOBERROR:
		return "CXEPsshd::InShellJob() error";

	case XEPSSHDEC_OUTSHELLJOBERROR:
		return "CXEPsshd::OutShellJob() error";

	default:
		return "CXEPsshd: Unknown error";
	}
}
