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

#include <fstream>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <termios.h>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/crypto/aes/CAes.h>
#include <common/crypto/rsa/CRsaKey.h>
#include <common/data/CBuffer.h>
#include <common/data/CBase64.h>
#include <common/xml/CXMLNode.h>
#include <common/xml/CXMLParser.h>

#include <CSSHConfig.h>

using namespace std;

CSSHConfig::CSSHConfig()
{

}

CSSHConfig::~CSSHConfig()
{
	try
	{
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
	}
}

void CSSHConfig::Interactive(const string& fileName)
{
	try
	{
		string password;
		
		if(IsFileExists(fileName))
		{
			RequestPassword("[" + fileName + "] Password: ", password);
			Load(fileName);
		}
		else
		{
			string password1, password2;
			bool isMatch = false;

			while(!isMatch)
			{
				RequestPassword("[" + fileName + "] Enter a new password: ", password1);
				RequestPassword("[" + fileName + "] Reenter the password: ", password2);

				if(password1 != password2)
				cout << "! passwords are differents !" << endl;
				else
				isMatch = true;
			}
			
			password = password1;
		}

		BuildMissing();
		CheckForHostSetting(password);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHConfigException(CSSHConfigException::SSHDCEC_INTERACTIVEERROR);
	}
}



void CSSHConfig::Save(const string& fileName)
{
	try
	{
		fstream FileIn;
		CBuffer Buffer;
		
		ConfigNode.Build(&Buffer);
		FileIn.open(fileName.c_str(), ios::out);
		FileIn.write((char*) Buffer.GetBuffer(), (long)Buffer.GetBufferSize());
		FileIn.close();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHConfigException(CSSHConfigException::SSHDCEC_LOADERROR);
	}
}

void CSSHConfig::RequestPassword(const string& message, string& password)
{
	termios old_tty;
	termios new_tty;
	
	tcgetattr(0, &old_tty);
	memcpy(&new_tty, &old_tty, sizeof(termios));

	new_tty.c_lflag &= ~(ICANON | ECHO);
//	new_tty.c_cc[VTIME] = 600 * 10;
	new_tty.c_cc[VMIN] = 1;

	tcsetattr(0, TCSANOW, &new_tty);
	RequestString(message, password);	
	tcsetattr(0, TCSANOW, &old_tty);
	
	cout << endl;
}

void CSSHConfig::RequestString(const string& message, string& string)
{
	cout << message << flush;

	char str[400];

	fgets(str, 400, stdin);
	str[strlen(str) - 1] = 0;
	string = str;
}

void CSSHConfig::BuildMissing()
{
	try
	{
		CXMLNode* pKeyRingNode;

		CXMLNode* pHostSettingNode;
		CXMLNode* pJidNode;
		CXMLNode* pHostNode;
		CXMLNode* pPortNode;
		CXMLNode* pPasswordNode;
		
		if(ConfigNode.GetName() != "xmpp-ssh")
		{
			ConfigNode.SetName("xmpp-ssh");
			ConfigNode.SetAttribut("version", "0.1");			
		}

		if(!ConfigNode.IsExistChild("host-setting"))
		{
			pHostSettingNode = new CXMLNode("host-setting");
			ConfigNode.PushChild(pHostSettingNode);
		}
		else
		{
			pHostSettingNode = ConfigNode.GetChild("host-setting");
		}

		if(!pHostSettingNode->IsExistChild("jid"))
		{
			pJidNode = new CXMLNode("jid");
			pHostSettingNode->PushChild(pJidNode);
		}
		
		if(!pHostSettingNode->IsExistChild("host"))
		{
			pHostNode = new CXMLNode("host");
			pHostSettingNode->PushChild(pHostNode);
		}
		
		if(!pHostSettingNode->IsExistChild("port"))
		{
			pPortNode = new CXMLNode("port");
			pHostSettingNode->PushChild(pPortNode);
		}
		
		if(!pHostSettingNode->IsExistChild("encrypted-password"))
		{
			pPasswordNode = new CXMLNode("encrypted-password");
			pHostSettingNode->PushChild(pPasswordNode);
		}
		

		
		if(!ConfigNode.IsExistChild("keyring"))
		{
			pKeyRingNode = new CXMLNode("keyring");
			ConfigNode.PushChild(pKeyRingNode);
		}
		else
		{
			pKeyRingNode = ConfigNode.GetChild("keyring");
		}
		
		for(u32 i = 0 ; i < pKeyRingNode->GetNumChild() ; i++)
		{
			CXMLNode* pItemNode = pKeyRingNode->GetChild(i);
		
			if(pItemNode->GetName() == "item")
			{
				if(!pItemNode->IsExistChild("jid"))
				{
					CXMLNode* pJidNode = new CXMLNode("jid");
					pItemNode->PushChild(pJidNode);
				}
				
				CXMLNode* pPubKeyNode;
				
				if(!pItemNode->IsExistChild("pubkey"))
				{
					pPubKeyNode = new CXMLNode("pubkey");
					pItemNode->PushChild(pPubKeyNode);
				}
				else
				{
					pPubKeyNode = pItemNode->GetChild("pubkey");
				}
				
				if(!pPubKeyNode->IsExistChild("n"))
				{
					CXMLNode* pNNode = new CXMLNode("n");
					pPubKeyNode->PushChild(pNNode);
				}

				if(!pPubKeyNode->IsExistChild("e"))
				{
					CXMLNode* pENode = new CXMLNode("e");
					pPubKeyNode->PushChild(pENode);
				}
			}
		}
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHConfigException(CSSHConfigException::SSHDCEC_INTERACTIVEERROR);
	}
}

void CSSHConfig::CheckForHostSetting(const string& password)
{
	try
	{
		CXMLNode* pHostSettingNode = ConfigNode.GetChild("host-setting");
		CXMLNode* pJidNode = pHostSettingNode->GetChild("jid");
		CXMLNode* pHostNode = pHostSettingNode->GetChild("host");
		CXMLNode* pPortNode = pHostSettingNode->GetChild("port");
		CXMLNode* pPasswordNode = pHostSettingNode->GetChild("encrypted-password");
		
		if(pJidNode->GetData().empty())
		{
			string jid;
			RequestString("[Host setting] Enter jid: ", jid);
			
			pJidNode->SetData(jid.c_str(), jid.size());
		}

		if(pHostNode->GetData().empty())
		{
			string host;
			RequestString("[Host setting] Enter host: ", host);

			pHostNode->SetData(host.c_str(), host.size());
		}

		if(pPortNode->GetData().empty())
		{
			string port;
			RequestString("[Host setting] Enter port: ", port);

			pPortNode->SetData(port.c_str(), port.size());
		}

		if(pPasswordNode->GetData().empty())
		{
			string hostPassword1, hostPassword2;
			bool isMatch = false;

			while(!isMatch)
			{
				RequestPassword("[Host setting] Enter Password: ", hostPassword1);
				RequestPassword("[Host setting] Renter Password: ", hostPassword2);

				if(hostPassword1 != hostPassword2)
				cout << "! passwords are differents !" << endl;
				else
				isMatch = true;
			}
			
			CBase64 Base64;
			string encPass64;
			CBuffer Buffer, EncryptedBuffer;
			CAes Aes;

			CXMLNode PasswordNode("password");
			PasswordNode.SetData(hostPassword1.c_str(), hostPassword1.size());

			PasswordNode.Build(&Buffer);
			Aes.SetKey(password);
			Aes.Encrypt(Buffer, &EncryptedBuffer);
			Base64.To64(&EncryptedBuffer, encPass64);
			pPasswordNode->SetData(encPass64.c_str(), encPass64.size());
		}
	
	
	
		CBase64 Base64;
		string pass64;
		CBuffer Buffer, EncryptedBuffer;
		CAes Aes;
		CXMLNode PasswordNode;
		
		Base64.From64(pPasswordNode->GetData(), &EncryptedBuffer);
		
		Aes.SetKey(password);
		Aes.Decrypt(EncryptedBuffer, &Buffer);
		CXMLParser::Parse(&Buffer, &PasswordNode);
		
		if(PasswordNode.GetName() != "password")
		throw CSSHConfigException(CSSHConfigException::SSHDCEC_INTERACTIVEERROR);
		

		Jid.SetFull(pJidNode->GetData());
		Jid.SetPassword(PasswordNode.GetData());

		u16 port;
		istringstream PortConvertor(pPortNode->GetData());
		PortConvertor >> port;
		
		HostAddress.SetHostName(pHostNode->GetData());
		HostAddress.SetPort(port);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHConfigException(CSSHConfigException::SSHDCEC_INTERACTIVEERROR);
	}
}

void CSSHConfig::AddPubKey(const CJid& rJid, const CRsaKey& rRsaKey)
{
	CXMLNode* pKeyRingNode = ConfigNode.GetChild("keyring");
	
	// we create the new item structure
	CXMLNode* pItemNode = new CXMLNode("item");
	CXMLNode* pJidNode = new CXMLNode("jid");
	CXMLNode* pPubKeyNode = new CXMLNode("pubkey");
	CXMLNode* pENode = new CXMLNode("e");
	CXMLNode* pNNode = new CXMLNode("n");
		
	pPubKeyNode->PushChild(pENode);
	pPubKeyNode->PushChild(pNNode);

	pItemNode->PushChild(pPubKeyNode);
	pItemNode->PushChild(pJidNode);

	pKeyRingNode->PushChild(pItemNode);
	
	// we build the item values
	CBase64 Base64;
	string NBase64, EBase64;
	CBuffer NBuffer, EBuffer;
	
	rRsaKey.GetN(&NBuffer);
	rRsaKey.GetE(&EBuffer);

	Base64.To64(&NBuffer, NBase64);
	Base64.To64(&EBuffer, EBase64);

	pNNode->SetData(NBase64.c_str(), NBase64.size());
	pENode->SetData(EBase64.c_str(), EBase64.size());
	pJidNode->SetData(rJid.GetShort().c_str(), rJid.GetShort().size());
}

CSSHConfig::KeyStatus CSSHConfig::IsExistPubKey(const CJid& rJid, const CRsaKey& rRsaKey)
{
	CXMLNode* pKeyRingNode = ConfigNode.GetChild("keyring");

	for(u32 i = 0 ; i < pKeyRingNode->GetNumChild() ; i++)
	{
		CXMLNode* pItemNode = pKeyRingNode->GetChild(i);
		CXMLNode* pJidNode = pItemNode->GetChild("jid");
		
		if(pJidNode->GetData() == rJid.GetShort())
		{
			CXMLNode* pPubKeyNode = pItemNode->GetChild("pubkey");
			CXMLNode* pENode = pPubKeyNode->GetChild("e");
			CXMLNode* pNNode = pPubKeyNode->GetChild("n");
		
			CBase64 Base64;
			CBuffer NBuffer1, EBuffer1;
			CBuffer NBuffer2, EBuffer2;
	
			Base64.From64(pENode->GetData(), &EBuffer1);
			Base64.From64(pNNode->GetData(), &NBuffer1);
	
			rRsaKey.GetN(&NBuffer2);
			rRsaKey.GetE(&EBuffer2);
		
			if(NBuffer1.GetBufferSize() != NBuffer2.GetBufferSize())
			return KS_CHANGED;
		
			for(u32 i = 0 ; i < NBuffer1.GetBufferSize() ; i++)
			{
				if(NBuffer1.GetByte() != NBuffer2.GetByte())
				return KS_CHANGED;
			}
			
			return KS_KNOWN;
		}
	}

	return KS_UNKNOWN;
}

bool CSSHConfig::IsFileExists(const string& fileName)
{
	bool isOpen;
	fstream File;
	
	File.open(fileName.c_str(), ios::in);
	isOpen =  File.is_open();
	File.close();

	return isOpen;
}

CObject::u32 CSSHConfig::GetFileSize(const string& fileName)
{
	try
	{
		u32 fileSize;
		fstream FileIn;

		FileIn.open(fileName.c_str(), ios::in);

		if(!FileIn.is_open())
		throw CSSHConfigException(CSSHConfigException::SSHDCEC_GETFILESIZEERROR);		

		FileIn.seekg(0, ios::end);
		fileSize = FileIn.tellg();
		FileIn.close();

		return fileSize;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHConfigException(CSSHConfigException::SSHDCEC_GETFILESIZEERROR);
	}
}

void CSSHConfig::Load(const string& fileName)
{
	try
	{
		fstream FileIn;
		u32 fileSize = GetFileSize(fileName);
		CBuffer Buffer(fileSize);

		FileIn.open(fileName.c_str(), ios::in);
		FileIn.read((char*) Buffer.GetBuffer(), (long)Buffer.GetBufferSize());
		FileIn.close();
		
		CXMLParser::Parse(&Buffer, &ConfigNode);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHConfigException(CSSHConfigException::SSHDCEC_LOADERROR);
	}
}

CSSHConfigException::CSSHConfigException(int code) : CException(code)
{}

CSSHConfigException::~CSSHConfigException() throw()
{}

const char* CSSHConfigException::what() const throw()
{
	switch(GetCode())
	{
	case SSHDCEC_LOADERROR:
		return "CSSHConfig::Load() error";

	case SSHDCEC_SAVEERROR:
		return "CSSHConfig::Save() error";

	case SSHDCEC_INTERACTIVEERROR:
		return "CSSHConfig::Interactive() error";

	default:
		return "CSSHConfig: unknown error";
	}	
}
