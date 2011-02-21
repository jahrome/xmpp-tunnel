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

#ifndef __CTCPADDRESS_H__
#define __CTCPADDRESS_H__

#include <string>

#include <common/CException.h>
#include <common/socket/CAddress.h>

using namespace std;

class CTCPAddress : public CAddress
{
public:
	CTCPAddress();
	CTCPAddress(const CTCPAddress* pAddress);
	CTCPAddress(const CTCPAddress& rAddress);	
	CTCPAddress(int sock);	
	CTCPAddress(const string& hostName, u16 port);
	virtual ~CTCPAddress();

	void operator=(const CTCPAddress* pAddress);
	void operator=(const CTCPAddress& rAddress);

	void Affect(const CTCPAddress* pAddress);
	void Affect(const CTCPAddress& rAddress);

	const string& GetHostName() const;
	u16 GetPort() const;
	int GetSocket() const;

	void SetHostName(const string& hostName);
	void SetPort(u16 port);
	void SetSocket(int socket);

private:
	string hostName;
	u16 port;
	int sock;
};

class CTCPAddressException : public CException
{
public:
	enum TCPAddressExceptionCode
	{
		TCPAEC_AFFECTERROR,
		TCPAEC_SETHOSTNAMEERROR,
		TCPAEC_SETPORTERROR,
		TCPAEC_SETSOCKETERROR
	};

public:
	CTCPAddressException(int code);
	virtual ~CTCPAddressException() throw();

	virtual const char* what() const throw();
};

#endif // __CTCPADDRESS_H__
