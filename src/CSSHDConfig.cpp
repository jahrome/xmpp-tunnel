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
#include <sstream>
#include <cstring>
#include <cstdio>
#include <termios.h>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/crypto/aes/CAes.h>
#include <common/crypto/rsa/CRsaKey.h>
#include <common/data/CBuffer.h>
#include <common/data/CBase64.h>
#include <common/xml/CXMLNode.h>
#include <common/xml/CXMLParser.h>

#include <CSSHDConfig.h>

using namespace std;

CSSHDConfig::CSSHDConfig()
{

}

CSSHDConfig::~CSSHDConfig()
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

void CSSHDConfig::Load(const string& fileName)
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
		
		throw CSSHDConfigException(CSSHDConfigException::SSHDCEC_LOADERROR);
	}
}

void CSSHDConfig::Save(const string& fileName)
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
		
		throw CSSHDConfigException(CSSHDConfigException::SSHDCEC_SAVEERROR);
	}
}

void CSSHDConfig::RequestPassword(const string& message, string& password)
{
	termios old_tty;
	termios new_tty;
	
	tcgetattr(0, &old_tty);
	memcpy(&new_tty, &old_tty, sizeof(termios));

	new_tty.c_lflag &= ~(ICANON | ECHO);
	//new_tty.c_cc[VTIME] = 6000;
	new_tty.c_cc[VMIN] = 1;

	tcsetattr(0, TCSANOW, &new_tty);
	RequestString(message, password);	
	tcsetattr(0, TCSANOW, &old_tty);
	
	cout << endl;
}

void CSSHDConfig::RequestString(const string& message, string& string)
{
	cout << message << flush;

	char str[400];

	fgets(str, 400, stdin);
	str[strlen(str) - 1] = 0;
	string = str;
}

void CSSHDConfig::BuildMissing()
{
	try
	{
		CXMLNode* pSSHDKeyNode;
		CXMLNode* pNNode;
		CXMLNode* pENode;
		CXMLNode* pDNode;

		CXMLNode* pHostSettingNode;
		CXMLNode* pJidNode;
		CXMLNode* pHostNode;
		CXMLNode* pPortNode;
		CXMLNode* pPasswordNode;
		
		if(ConfigNode.GetName() != "xmpp-sshd")
		{
			ConfigNode.SetName("xmpp-sshd");
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
		

		
		if(!ConfigNode.IsExistChild("sshd-key"))
		{
			pSSHDKeyNode = new CXMLNode("sshd-key");
			ConfigNode.PushChild(pSSHDKeyNode);
		}
		else
		{
			pSSHDKeyNode = ConfigNode.GetChild("sshd-key");
		}

		if(!pSSHDKeyNode->IsExistChild("n"))
		{
			pNNode = new CXMLNode("n");
			pSSHDKeyNode->PushChild(pNNode);
		}

		if(!pSSHDKeyNode->IsExistChild("e"))
		{
			pENode = new CXMLNode("e");
			pSSHDKeyNode->PushChild(pENode);
		}

		if(!pSSHDKeyNode->IsExistChild("encrypted-d"))
		{
			pDNode = new CXMLNode("encrypted-d");
			pSSHDKeyNode->PushChild(pDNode);
		}
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHDConfigException(CSSHDConfigException::SSHDCEC_INTERACTIVEERROR);
	}
}

void CSSHDConfig::CheckForHostSetting(const string& password)
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
		throw CSSHDConfigException(CSSHDConfigException::SSHDCEC_INTERACTIVEERROR);
		

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
		
		throw CSSHDConfigException(CSSHDConfigException::SSHDCEC_INTERACTIVEERROR);
	}
}

void CSSHDConfig::CheckForKey(const string& password)
{
	try
	{
		CXMLNode* pSSHDKeyNode = ConfigNode.GetChild("sshd-key");
		CXMLNode* pENode = pSSHDKeyNode->GetChild("e");
		CXMLNode* pNNode = pSSHDKeyNode->GetChild("n");
		CXMLNode* pDNode = pSSHDKeyNode->GetChild("encrypted-d");
		
		if(pENode->GetData().empty() || pNNode->GetData().empty()
			|| pDNode->GetData().empty())
		{
			u16 keySize, e;
			string keySizeString, eString;

			RequestString("[SSH Server Key] Enter key size: ", keySizeString);
			RequestString("[SSH Server Key] Enter an exposent (ie: 3, 17 and 65537): ", eString);
			
			if(keySizeString.empty())
			keySizeString = "2048";

			if(eString.empty())
			eString = "65537";

			istringstream KeySizeConvertor(keySizeString);
			KeySizeConvertor >> keySize;

			istringstream eConvertor(eString);
			eConvertor >> e;
		
			cout << "[SSH Server Key] Generating key..." << flush;
			RsaKey.GenerateKey(keySize, e);
			cout << "done" << endl;
			
			CBase64 Base64;
			CAes Aes;

			CXMLNode DNode("d");

			string NBase64, EBase64, DBase64, EncryptedDBase64;
			CBuffer NBuffer, EBuffer, DBuffer, EncryptedDBuffer;
			
			RsaKey.GetN(&NBuffer);
			RsaKey.GetE(&EBuffer);
			RsaKey.GetD(&DBuffer);

			Base64.To64(&NBuffer, NBase64);
			Base64.To64(&EBuffer, EBase64);
			Base64.To64(&DBuffer, DBase64);

			pNNode->SetData(NBase64.c_str(), NBase64.size());
			pENode->SetData(EBase64.c_str(), EBase64.size());

			DNode.SetData(DBase64.c_str(), DBase64.size());

			Aes.SetKey(password);

			DNode.Build(&DBuffer);

			Aes.Encrypt(DBuffer, &EncryptedDBuffer);
			Base64.To64(&EncryptedDBuffer, EncryptedDBase64);
			pDNode->SetData(EncryptedDBase64.c_str(), EncryptedDBase64.size());
		}
		
		CBase64 Base64;
		CAes Aes;

		CXMLNode DNode;
		string NBase64, EBase64, DBase64, EncryptedDBase64;
		CBuffer NBuffer, EBuffer, DBuffer, EncryptedDBuffer;
			
		Base64.From64(pNNode->GetData(), &NBuffer);
		Base64.From64(pENode->GetData(), &EBuffer);
		Base64.From64(pDNode->GetData(), &EncryptedDBuffer);

		Aes.SetKey(password);

		Aes.Decrypt(EncryptedDBuffer, &DBuffer);
	
		CXMLParser::Parse(&DBuffer, &DNode);
		Base64.From64(DNode.GetData(), &DBuffer);

		if(DNode.GetName() != "d")
		throw CSSHDConfigException(CSSHDConfigException::SSHDCEC_INTERACTIVEERROR);	

		RsaKey.SetN(NBuffer);
		RsaKey.SetE(EBuffer);
		RsaKey.SetD(DBuffer);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHDConfigException(CSSHDConfigException::SSHDCEC_INTERACTIVEERROR);
	}
}


void CSSHDConfig::Interactive(const string& fileName)
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
		CheckForKey(password);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHDConfigException(CSSHDConfigException::SSHDCEC_INTERACTIVEERROR);
	}
}

bool CSSHDConfig::IsFileExists(const string& fileName)
{
	bool isOpen;
	fstream File;
	
	File.open(fileName.c_str(), ios::in);
	isOpen =  File.is_open();
	File.close();

	return isOpen;
}

CObject::u32 CSSHDConfig::GetFileSize(const string& fileName)
{
	try
	{
		u32 fileSize;
		fstream FileIn;

		FileIn.open(fileName.c_str(), ios::in);

		if(!FileIn.is_open())
		throw CSSHDConfigException(CSSHDConfigException::SSHDCEC_GETFILESIZEERROR);		

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
		
		throw CSSHDConfigException(CSSHDConfigException::SSHDCEC_GETFILESIZEERROR);
	}
}

CSSHDConfigException::CSSHDConfigException(int code) : CException(code)
{}

CSSHDConfigException::~CSSHDConfigException() throw()
{}

const char* CSSHDConfigException::what() const throw()
{
	switch(GetCode())
	{
	case SSHDCEC_LOADERROR:
		return "CSSHDConfig::Load() error";

	case SSHDCEC_SAVEERROR:
		return "CSSHDConfig::Save() error";

	case SSHDCEC_INTERACTIVEERROR:
		return "CSSHDConfig::Interactive() error";

	default:
		return "CSSHDConfig: unknown error";
	}
	
}
