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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>

#include <CSSHConfig.h>
#include <CInterface.h>

#include <common/crypto/rsa/CRsaKey.h>
#include <common/socket/tcp/CTCPAddress.h>

#include <resox/CResox.h>

#include <xmpp/im/CXMPPInstMsg.h>
#include <xmpp/jid/CJid.h>

int main(int argc, char** argv)
{
	CJid xmppJid, sshJid;
	CTCPAddress HostAddress;
	CSSHConfig SSHConfig;

	string fileName = "ssh.xml";

	try
	{
		SSHConfig.Interactive(fileName);
		SSHConfig.Save(fileName);
	}

	catch(exception& e)
	{
		cerr << "Wrong password" << endl;
		return 1;
	}

	try
	{
		xmppJid = SSHConfig.GetJid();
		HostAddress = SSHConfig.GetHostAddress();
		
		// connection to the jabber server
		CResox Resox;
		cout << "connecting to " << HostAddress.GetHostName() << ":" << HostAddress.GetPort()  << " ... " << flush;
		Resox.ConnectTo(&xmppJid, &HostAddress);
		cout << "done" << endl;
		
		// requesting which entities to connect				
		CInterface Interface(&Resox);
		sshJid = Interface.SelectHost();

		// we are connecting to the sshd server				
		CRsaKey AuthServerKey;
		cout << "checking signature on " << sshJid.GetShort() << "..." << endl;
		Resox.ConnectToSSH(sshJid, &AuthServerKey);		

		CBuffer FingerPrint;
		AuthServerKey.GetFingerPrint(&FingerPrint);

		cout << " RSA PubKey fingerprint [";
		for(CObject::u32 i = 0 ; i < FingerPrint.GetBufferSize() ; i++)
		printf("%X", FingerPrint.GetByte());
		cout << "]" << endl;

		// we check his public key
		CSSHConfig::KeyStatus keyStatus = SSHConfig.IsExistPubKey(sshJid, AuthServerKey);	

		if(keyStatus == CSSHConfig::KS_KNOWN)
		{
			cout << "Authenticated" << endl;
		}
		
		if(keyStatus == CSSHConfig::KS_UNKNOWN)
		{
			cout << "!!! UNKNOWN HOST !!!" << endl;			
			string answere;
			Interface.RequestString("Add this key to KeyRing ? [Y/N]:", answere);
			
			if(answere == "Y" || answere == "y")
			{
				SSHConfig.AddPubKey(sshJid, AuthServerKey);
				SSHConfig.Save(fileName);
			}
			else
			return 0;
		}
		
		if(keyStatus == CSSHConfig::KS_CHANGED)
		{
			cout << "!!!!!!!!!!!!!! SSHD PUBLIC KEY HAS CHANGED !!!!!!!!!!!!!!" << endl;			
			cout << " Active man in the middle attack possible" << endl;			

			return 0;
		}

		// we get the username/password		
		string userName, password;
		Interface.RequestString("username: ", userName);
		Interface.RequestPassword("password: ", password);
	
		Resox.Login(userName, password);
		cout << "Connection Closed" << endl;
		return 0;
	}

	catch(exception& e)
	{
		cout << "Connection Closed on error" << endl;
		cerr << e.what() << endl;
		return 1;
	}
}
