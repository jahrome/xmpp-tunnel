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

#include <common/socket/tcp/CTCPAddress.h>

#include <resox/CResox.h>

#include <xmpp/im/CXMPPInstMsg.h>
#include <xmpp/jid/CJid.h>

int main(int argc, char** argv)
{
	CJid xmppJid, tunnelJid;
	CTCPAddress HostAddress;
	CSSHConfig SSHConfig;

	string fileName = "/etc/xmpp-tunnel.xml";

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
		CResox Resox(SSHConfig.GetAddress(), SSHConfig.GetMask());
		cout << "connecting to " << HostAddress.GetHostName() << ":" << HostAddress.GetPort()  << " ... " << flush;
		Resox.ConnectTo(&xmppJid, &HostAddress);
		cout << "done" << endl;

		// requesting which entities to connect				
		CInterface Interface(&Resox);

		tunnelJid = Interface.SelectHost();

		// we are connecting to the xmpp-tunneld server				
		Resox.ConnectToSSH(tunnelJid);

		Resox.Login();
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
