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

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <iostream>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>
#include <common/socket/tcp/CTCPAddress.h>
#include <common/socket/tcp/CTCPConnection.h>

CTCPConnection::CTCPConnection()
{
	isConnected = false;
}

CTCPConnection::CTCPConnection(CTCPAddress* pTCPAddress)
{
	try
	{
		TCPAddress = *pTCPAddress;
		isConnected = false;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_CONSTRUCTORERROR);
	}
}

CTCPConnection::CTCPConnection(CTCPAddress& rTCPAddress)
{
	try
	{
		TCPAddress = rTCPAddress;
		isConnected = false;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_CONSTRUCTORERROR);
	}
}

CTCPConnection::~CTCPConnection()
{
	try
	{
		Disconnect();
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}
void CTCPConnection::SetTCPAddress(const CTCPAddress* pTCPAddress)
{
	try
	{
		TCPAddress = *pTCPAddress;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_SETTCPADDRESSERROR);
	}
}

void CTCPConnection::SetTCPAddress(const CTCPAddress& rTCPAddress)
{
	SetTCPAddress(&rTCPAddress);
}

const CTCPAddress& CTCPConnection::GetTCPAddress() const
{
	return TCPAddress;
}

void CTCPConnection::Connect(const CTCPAddress* pTCPAddress)
{
	SetTCPAddress(*pTCPAddress);
	Connect();
}

void CTCPConnection::Connect(const CTCPAddress& rTCPAddress)
{
	SetTCPAddress(rTCPAddress);
	Connect();
}

void CTCPConnection::Connect()
{
	try
	{
		if(IsConnected())
		return;
	
		sockaddr_in address;
		hostent *pHost;
		int sock;
	
		if ((pHost = gethostbyname(TCPAddress.GetHostName().c_str())) == NULL)
		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_CONNECTERROR);

		memset(&address, 0x00, sizeof(sockaddr_in));
		memcpy(&address.sin_addr, pHost->h_addr, pHost->h_length);

		address.sin_family = pHost->h_addrtype;
		address.sin_port = htons(TCPAddress.GetPort());

		// create a TCP/IP socket type
		if((sock = socket(pHost->h_addrtype, SOCK_STREAM, 0)) < 0)
		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_CONNECTERROR);

		TCPAddress.SetSocket(sock);
		
		// establish the remote connection
		if(connect(TCPAddress.GetSocket(), (sockaddr*) &address, sizeof(sockaddr_in)) < 0)
		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_CONNECTERROR);
		
		isConnected = true;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_CONNECTERROR);
	}
}

void CTCPConnection::Disconnect()
{
	try
	{
		if(!IsConnected())
		return;
	
		isConnected = false;
		
		if(close(TCPAddress.GetSocket()) != 0)
		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_DISCONNECTERROR);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_DISCONNECTERROR);
	}

}

	
bool CTCPConnection::Send(const CBuffer* pBuffer)
{
	try
	{
		u8* buffer = pBuffer->GetBuffer();
		u32 sizeSend = 0;
		u32 bufferSize = pBuffer->GetBufferSize();
		int currentSizeSend;

		while(sizeSend < bufferSize)
		{
			currentSizeSend = write(TCPAddress.GetSocket(), buffer + sizeSend, bufferSize - sizeSend);

			if(currentSizeSend <= 0)
			{
				isConnected = false;
				return false;
			}
			sizeSend += currentSizeSend;
		}
		
		return true;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_SENDERROR);		
	}
}

bool CTCPConnection::Receive(CBuffer* pBuffer)
{
	try
	{
		CBuffer Temp(pBuffer->GetBufferSize());

		int sizeReceive = read(TCPAddress.GetSocket(), Temp.GetBuffer(), Temp.GetBufferSize());

		if(sizeReceive <= 0)
		{
			isConnected = false;
			return false;
		}
		
		pBuffer->Create(sizeReceive);
		pBuffer->Write(Temp.GetBuffer(), sizeReceive);
		
		return true;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTCPConnectionException(CTCPConnectionException::TCPCEC_RECEIVEERROR);		
	}

}

bool CTCPConnection::IsConnected() const
{
	return isConnected;
}

CTCPConnectionException::CTCPConnectionException(int code) : CException(code)
{
}

CTCPConnectionException::~CTCPConnectionException() throw()
{}

const char* CTCPConnectionException::what()
{
	switch(GetCode())
	{
	case TCPCEC_SETTCPADDRESSERROR:
		return "CTCPConnection::SetTCPAddress() error";
		
	case TCPCEC_SENDERROR:
		return "CTCPConnection::Send() error";
		
	case TCPCEC_RECEIVEERROR:
		return "CTCPConnection::Receive() error";

	case TCPCEC_CONNECTERROR:
		return "CTCPConnection::Connect() class";

	case TCPCEC_DISCONNECTERROR:
		return "CTCPConnection::Disconnect() class";
	
	default:
		return "CTCPConnection: unknown error";
	}
}


