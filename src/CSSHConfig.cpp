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
#include <common/data/CBuffer.h>
#include <common/data/CBase64.h>
#include <common/xml/CXMLNode.h>
#include <common/xml/CXMLParser.h>

#include <CSSHConfig.h>

using namespace std;

CSSHConfig::CSSHConfig()
{

}

void CSSHConfig::SetPassword(string password)
{
	Password = password;
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
		CXMLNode* pHostSettingNode;
		CXMLNode* pJidNode;
		CXMLNode* pHostNode;
		CXMLNode* pPortNode;
		CXMLNode* pPasswordNode;
		CXMLNode* pAddressNode;
		CXMLNode* pMaskNode;
		
		if(ConfigNode.GetName() != "xmpp-tunnel")
		{
			ConfigNode.SetName("xmpp-tunnel");
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
		
		if(!pHostSettingNode->IsExistChild("address"))
		{
			pAddressNode = new CXMLNode("address");
			pHostSettingNode->PushChild(pAddressNode);
		}
		else
		{
			pAddressNode = pHostSettingNode->GetChild("address");
		}
		
		if(!pHostSettingNode->IsExistChild("mask"))
		{
			pMaskNode = new CXMLNode("mask");
			pHostSettingNode->PushChild(pMaskNode);
		}
		else
		{
			pMaskNode = pHostSettingNode->GetChild("mask");
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
		CXMLNode* pAddressNode = pHostSettingNode->GetChild("address");
		CXMLNode* pMaskNode = pHostSettingNode->GetChild("mask");

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
	
		if(pAddressNode->GetData().empty())
		{
			RequestString("[Host setting] Enter local address: ", Address);

			pAddressNode->SetData(Address.c_str(), Address.size());
		}
	
		if(pMaskNode->GetData().empty())
		{
			RequestString("[Host setting] Enter netmask: ", Mask);

			pMaskNode->SetData(Mask.c_str(), Mask.size());
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

		Address = pAddressNode->GetData();
		Mask = pMaskNode->GetData();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHConfigException(CSSHConfigException::SSHDCEC_INTERACTIVEERROR);
	}
}

void CSSHConfig::Interactive(const string& fileName)
{
	try
	{
		if(IsFileExists(fileName))
		{
			if (Password.size() == 0)
				RequestPassword("[" + fileName + "] Password: ", Password);
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
			
			Password = password1;
		}

		BuildMissing();
		CheckForHostSetting(Password);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
		
		throw CSSHConfigException(CSSHConfigException::SSHDCEC_INTERACTIVEERROR);
	}
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

string CSSHConfig::GetAddress()
{
	return Address;
}

string CSSHConfig::GetMask()
{
	return Mask;
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
