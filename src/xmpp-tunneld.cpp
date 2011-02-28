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

#include <common/CObject.h>
#include <common/CException.h>

#include <CSSHConfig.h>
#include <common/socket/tcp/CTCPAddress.h>
#include <xmpp/jid/CJid.h>
#include <resoxserver/CResoxServer.h>


int main(int argc, char** argv)
{
	string fileName = "xmpp-tunneld.xml";
	CSSHConfig SSHConfig;
	CJid Jid;
	CTCPAddress TCPAddress;	

	if (argc == 2)
	{
		SSHConfig.SetPassword(argv[1]);
	}
		
	try
	{	
		SSHConfig.Interactive(fileName);
		SSHConfig.Save(fileName);
	}
	
	catch(exception& e)
	{
		cerr << "exit on error! (possible invalid password)" << endl;
		return 1;
	}
		
	try
	{
		Jid = SSHConfig.GetJid();
		TCPAddress = SSHConfig.GetHostAddress();

		CResoxServer ResoxServer(SSHConfig.GetAddress(), SSHConfig.GetMask());
		ResoxServer.Run(&Jid, &TCPAddress);

		return 0;
	}
	
	catch(exception& e)
	{
		cerr << "exit on error: " << e.what() << endl;
		return 1;
	}
}
