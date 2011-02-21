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

#include <string.h>
#include <iostream>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/socket/tcp/CTCPAddress.h>

using namespace std;

CTCPAddress::CTCPAddress()
{
	port = 0;
}

CTCPAddress::CTCPAddress(const CTCPAddress* pAddress)
{
	Affect(pAddress);
}

CTCPAddress::CTCPAddress(const CTCPAddress& rAddress)
{
	Affect(rAddress);
}

CTCPAddress::CTCPAddress(const string& hostName, u16 port)
{
	SetHostName(hostName);
	SetPort(port);
}

CTCPAddress::CTCPAddress(int sock)
{
	SetSocket(sock);
}

CTCPAddress::~CTCPAddress()
{
}

void CTCPAddress::operator=(const CTCPAddress* pAddress)
{
	Affect(pAddress);
}

void CTCPAddress::operator=(const CTCPAddress& rAddress)
{
	Affect(rAddress);
}


void CTCPAddress::Affect(const CTCPAddress* pAddress)
{
	Affect(*pAddress);
}

void CTCPAddress::Affect(const CTCPAddress& rAddress)
{
	try
	{
		SetHostName(rAddress.GetHostName());
		SetPort(rAddress.GetPort());
		SetSocket(rAddress.GetSocket());	
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPAddressException(CTCPAddressException::TCPAEC_AFFECTERROR);
	}
}

const string& CTCPAddress::GetHostName() const
{
	return hostName;
}

CObject::u16 CTCPAddress::GetPort() const
{
	return port;
}

int CTCPAddress::GetSocket() const
{
	return sock;
}

void CTCPAddress::SetHostName(const string& hostName)
{
	try
	{
		this->hostName = hostName;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPAddressException(CTCPAddressException::TCPAEC_SETHOSTNAMEERROR);
	}
}

void CTCPAddress::SetPort(u16 port)
{
	try
	{
		if(port == 0)
		throw CTCPAddressException(CTCPAddressException::TCPAEC_SETPORTERROR);
		
		this->port = port;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPAddressException(CTCPAddressException::TCPAEC_SETPORTERROR);
	}
}

void CTCPAddress::SetSocket(int sock)
{
	try
	{
		this->sock = sock;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPAddressException(CTCPAddressException::TCPAEC_SETSOCKETERROR);
	}
}


CTCPAddressException::CTCPAddressException(int code) : CException(code)
{}

CTCPAddressException::~CTCPAddressException() throw()
{
}

const char* CTCPAddressException::what() const throw()
{
	switch(GetCode())
	{
	case TCPAEC_AFFECTERROR:
		return "CTCPAddress::Affect() error";

	case TCPAEC_SETHOSTNAMEERROR:
		return "CTCPAddress::SetHostName() error";
		
	case TCPAEC_SETPORTERROR:
		return "CTCPAddress::SetPort() error";
		
	case TCPAEC_SETSOCKETERROR:
		return "CTCPAddress::SetSocket() error";

	default:
		return "CTCPAddress: Unknown error";

	}
}

