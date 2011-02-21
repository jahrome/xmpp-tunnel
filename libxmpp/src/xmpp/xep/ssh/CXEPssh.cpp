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
#include <common/crypto/aes/CAes.h>
#include <common/crypto/rsa/CRsa.h>
#include <common/crypto/rsa/CRsaKey.h>
#include <common/data/CBase64.h>
#include <common/thread/CMutex.h>
#include <common/thread/CThread.h>
#include <common/xml/CXMLNode.h>
#include <common/xml/CXMLParser.h>

#include <xmpp/core/CHandler.h>
#include <xmpp/core/CXMLFilter.h>
#include <xmpp/core/CXMPPCore.h>
#include <xmpp/xep/ssh/CXEPssh.h>
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

void CXEPssh::ConnectToSSH(const CJid& rRemoteJid, CRsaKey* pAuthServerKey)
{
	try
	{
		RemoteJid = rRemoteJid;
		
		XEPxibb.OpenChannel(RemoteJid, &channelId);
		
		SessionKeyExchange();
		SessionAuthServer(pAuthServerKey);
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

void CXEPssh::SetShellSize(u32 row, u32 column, u32 xpixel, u32 ypixel)
{
	CBuffer Buffer, EncryptedBuffer;
	CSessionShellDataNode SessionShellDataNode;
	
	SessionShellDataNode.SetRow(row);
	SessionShellDataNode.SetColumn(column);
	SessionShellDataNode.SetX(xpixel);
	SessionShellDataNode.SetY(ypixel);

	SessionShellDataNode.Build(&Buffer);
	AesOnShell.Encrypt(Buffer, &EncryptedBuffer);
	XEPxibb.SendStreamData(RemoteJid, channelId, shellSid, &EncryptedBuffer);
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
		AesOnShell.Encrypt(Buffer, &EncryptedBuffer);
		XEPxibb.SendStreamData(RemoteJid, channelId, shellSid, &EncryptedBuffer);
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

		XEPxibb.ReceiveStreamData(RemoteJid, channelId, shellSid, &EncryptedBuffer);
		AesOnShell.Decrypt(EncryptedBuffer, &Buffer);		
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

void CXEPssh::SessionKeyExchange()
{
	try
	{		
		CBuffer Buffer;
		CSessionKeyExchangeFeaturesGetNode SessionKeyExchangeFeaturesGetNode;
		CSessionKeyExchangeFeaturesResultNode SessionKeyExchangeFeaturesResultNode;
		CSessionKeyExchangeStartNode SessionKeyExchangeStartNode;
		CSessionKeyExchangeDoNode SessionKeyExchangeDoNode;
		CSessionKeyExchangeDoneNode SessionKeyExchangeDoneNode;

		// we request the keyexchange features 
		SessionKeyExchangeFeaturesGetNode.Build(&Buffer);
		XEPxibb.SendChannelData(RemoteJid, channelId, &Buffer);
		
		XEPxibb.ReceiveChannelData(RemoteJid, channelId, &Buffer);
		CXMLParser::Parse(&Buffer, &SessionKeyExchangeFeaturesResultNode);
		
		// we negociate the shared key
		SessionKeyExchangeStartNode.Build(&Buffer);
		XEPxibb.SendChannelData(RemoteJid, channelId, &Buffer);	
		
		XEPxibb.ReceiveChannelData(RemoteJid, channelId, &Buffer);
		CXMLParser::Parse(&Buffer, &SessionKeyExchangeDoNode);
		
		CRsaKey RsaKey;
		CBuffer PlainKey1, PlainKey2, EncryptedKey2, SessionKey;
		
		SessionKeyExchangeDoNode.GetPublicKey(&RsaKey);
		SessionKeyExchangeDoNode.GetPlainKey1(&PlainKey1);

		CRsa::GenerateChallenge(32, &PlainKey2);
		CRsa::EncryptChallenge(RsaKey, PlainKey2, &EncryptedKey2);
		
		SessionKeyExchangeDoneNode.SetEncryptedKey2(EncryptedKey2);
		
		SessionKeyExchangeDoneNode.Build(&Buffer);
		XEPxibb.SendChannelData(RemoteJid, channelId, &Buffer);
		
		SessionKey.Create(32);

		for(u8 i = 0 ; i < SessionKey.GetBufferSize() ; i++)
		SessionKey.Write((u8) (PlainKey1.GetBuffer()[i] ^ PlainKey2.GetBuffer()[i]));
		
		AesOnShell.SetKey(SessionKey);
		AesOnChannel.SetKey(SessionKey);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshException(CXEPsshException::XEPSSHEC_SESSIONKEYEXCHANGEERROR);
	}
}

void CXEPssh::SessionAuthServer(CRsaKey* pAuthServerKey)
{
	try
	{
		CBuffer DataBuffer, EncryptedDataBuffer;

		CSessionAuthServerFeaturesGetNode SessionAuthServerFeaturesGetNode;
		CSessionAuthServerFeaturesResultNode SessionAuthServerFeaturesResultNode;
		CSessionAuthServerStartNode SessionAuthServerStartNode;
		CSessionAuthServerDoneNode SessionAuthServerDoneNode;

		// we request the auth server features 
		SessionAuthServerFeaturesGetNode.Build(&DataBuffer);
		AesOnChannel.Encrypt(DataBuffer, &EncryptedDataBuffer);
		XEPxibb.SendChannelData(RemoteJid, channelId, &EncryptedDataBuffer);
		
		XEPxibb.ReceiveChannelData(RemoteJid, channelId, &EncryptedDataBuffer);
		AesOnChannel.Decrypt(EncryptedDataBuffer, &DataBuffer);
		CXMLParser::Parse(&DataBuffer, &SessionAuthServerFeaturesResultNode);
		
		SessionAuthServerFeaturesResultNode.GetPublicKey(pAuthServerKey);
		
		// we send a challenge and check the signature
		CBuffer Challenge, Signature;

		CRsa::GenerateChallenge(50, &Challenge);
		SessionAuthServerStartNode.SetChallenge(Challenge);

		SessionAuthServerStartNode.Build(&DataBuffer);
		AesOnChannel.Encrypt(DataBuffer, &EncryptedDataBuffer);
		XEPxibb.SendChannelData(RemoteJid, channelId, &EncryptedDataBuffer);	
		
		XEPxibb.ReceiveChannelData(RemoteJid, channelId, &EncryptedDataBuffer);
		AesOnChannel.Decrypt(EncryptedDataBuffer, &DataBuffer);
		CXMLParser::Parse(&DataBuffer, &SessionAuthServerDoneNode);

		SessionAuthServerDoneNode.GetSignature(&Signature);

		if(!CRsa::VerifyChallenge(*pAuthServerKey, Challenge, Signature))
		throw CXEPsshException(CXEPsshException::XEPSSHEC_SESSIONAUTHSERVERERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXEPsshException(CXEPsshException::XEPSSHEC_SESSIONAUTHSERVERERROR);
	}
}

void CXEPssh::Login(const string& userName, const string& password)
{
	try
	{
		CBuffer DataBuffer, EncryptedDataBuffer;

		CSessionAuthClientFeaturesGetNode SessionAuthClientFeaturesGetNode;
		CSessionAuthClientFeaturesResultNode SessionAuthClientFeaturesResultNode;
		CSessionAuthClientStartNode SessionAuthClientStartNode;
		CSessionAuthClientDoneNode SessionAuthClientDoneNode;

		// we request the auth client features 
		SessionAuthClientFeaturesGetNode.Build(&DataBuffer);
		AesOnChannel.Encrypt(DataBuffer, &EncryptedDataBuffer);
		XEPxibb.SendChannelData(RemoteJid, channelId, &EncryptedDataBuffer);
		
		XEPxibb.ReceiveChannelData(RemoteJid, channelId, &EncryptedDataBuffer);
		AesOnChannel.Decrypt(EncryptedDataBuffer, &DataBuffer);
		CXMLParser::Parse(&DataBuffer, &SessionAuthClientFeaturesResultNode);
				
		// we the username/password
		SessionAuthClientStartNode.SetUserName(userName);
		SessionAuthClientStartNode.SetPassword(password);

		SessionAuthClientStartNode.Build(&DataBuffer);
		AesOnChannel.Encrypt(DataBuffer, &EncryptedDataBuffer);
		XEPxibb.SendChannelData(RemoteJid, channelId, &EncryptedDataBuffer);	
		
		XEPxibb.ReceiveChannelData(RemoteJid, channelId, &EncryptedDataBuffer);
		AesOnChannel.Decrypt(EncryptedDataBuffer, &DataBuffer);
		CXMLParser::Parse(&DataBuffer, &SessionAuthClientDoneNode);
		
		// we waiting an opening shell stream
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

	case XEPSSHEC_SESSIONKEYEXCHANGEERROR:
		return "CXEPssh::SessionKeyExchange() error";

	case XEPSSHEC_SESSIONAUTHSERVERERROR:
		return "CXEPssh::SessionAuthServer() error";

	case XEPSSHEC_SESSIONAUTHCLIENTERROR:
		return "CXEPssh::SessionAuthClient() error";

	default:
		return "CXEPssh: Unknown error";
	}
}
