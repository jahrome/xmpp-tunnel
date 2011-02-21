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
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>
#include <common/socket/tcp/CTCPAddress.h>
#include <common/socket/tcp/CTCPConnection.h>
#include <common/socket/tcp/tls/CTLSConnection.h>

using namespace std;

CTLSConnection::CTLSConnection() : CTCPConnection()
{
	ssl = NULL;
	isSecured = false;
}

CTLSConnection::CTLSConnection(CTCPAddress* pTCPAddress) : CTCPConnection(pTCPAddress)
{
	ssl = NULL;
	isSecured = false;
}

CTLSConnection::CTLSConnection(CTCPAddress& rTCPAddress) : CTCPConnection(rTCPAddress)
{
	ssl = NULL;
	isSecured = false;
}

CTLSConnection::~CTLSConnection()
{
	try
	{
		if(IsSecured())
		Unsecure();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}
bool CTLSConnection::Send(const CBuffer* pBuffer)
{
	try
	{
		u8* buffer = pBuffer->GetBuffer();
		u32 sizeSend = 0;
		u32 bufferSize = pBuffer->GetBufferSize();
		int currentSizeSend;

		while(sizeSend < bufferSize)
		{
			if(IsSecured())
			currentSizeSend = SSL_write(ssl, buffer + sizeSend, bufferSize - sizeSend);
			else
			currentSizeSend = write(GetTCPAddress().GetSocket(), buffer + sizeSend, bufferSize - sizeSend);

			if(currentSizeSend <= 0)
			{
				if(IsSecured())
				Unsecure();

				Disconnect();
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

		throw CTLSConnectionException(CTLSConnectionException::TLSCEC_SENDERROR);		
	}
}

bool CTLSConnection::Receive(CBuffer* pBuffer)
{
	try
	{
		CBuffer Temp(pBuffer->GetBufferSize());
		int sizeReceive;

		if(IsSecured())
		sizeReceive = SSL_read(ssl, Temp.GetBuffer(), Temp.GetBufferSize());
		else
		sizeReceive = read(GetTCPAddress().GetSocket(), Temp.GetBuffer(), Temp.GetBufferSize());

		if(sizeReceive <= 0)
		{
			if(IsSecured())
			Unsecure();
		
			Disconnect();
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

		throw CTLSConnectionException(CTLSConnectionException::TLSCEC_RECEIVEERROR);		
	}
}

bool CTLSConnection::IsSecured()
{
	return isSecured == true;
}

bool CTLSConnection::IsNotSecured()
{
	return !IsSecured();
}

void CTLSConnection::Unsecure()
{
	try
	{
		if(IsNotSecured())
		return;

		SSL_shutdown(ssl);
		SSL_free(ssl);
		isSecured = false;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTLSConnectionException(CTLSConnectionException::TLSCEC_UNSECUREERROR);		
	}
}

void CTLSConnection::Secure()
{
	try
	{
		if(IsSecured())
		return;
		
		SSL_CTX* ctx = NULL;
		SSL_METHOD *meth = NULL;
		ssl = NULL;
		
		SSLeay_add_ssl_algorithms();
		SSL_load_error_strings();
		
		meth = (SSL_METHOD*)SSLv3_client_method();
		
		if(meth == NULL)
		throw CTLSConnectionException(CTLSConnectionException::TLSCEC_SECUREERROR);
		
		ctx = SSL_CTX_new(meth);

		if(ctx == NULL)
		throw CTLSConnectionException(CTLSConnectionException::TLSCEC_SECUREERROR);
		
		ssl = SSL_new(ctx);
		SSL_CTX_free(ctx);

		if(ssl == NULL)
		throw CTLSConnectionException(CTLSConnectionException::TLSCEC_SECUREERROR);

		SSL_set_fd(ssl, GetTCPAddress().GetSocket());
		
		if(SSL_connect(ssl) == -1)
		{
			SSL_free(ssl);
			throw CTLSConnectionException(CTLSConnectionException::TLSCEC_SECUREERROR);
		}
		
		isSecured = true;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CTLSConnectionException(CTLSConnectionException::TLSCEC_SECUREERROR);		
	}
}

CTLSConnectionException::CTLSConnectionException(int code) : CException(code)
{
}

CTLSConnectionException::~CTLSConnectionException() throw()
{}

const char* CTLSConnectionException::what() const throw()
{
	switch(GetCode())
	{		
	case TLSCEC_SECUREERROR:
		return "CTLSConnection::Secure() error";

	case TLSCEC_UNSECUREERROR:
		return "CTLSConnection:Unsecure() error";
		
	case TLSCEC_SENDERROR:
		return "CTLSConnection::Send() error";

	case TLSCEC_RECEIVEERROR:
		return "CTLSConnection::Receive() error";

	default:
		return "CTLSConnection: Unknown error";
	}
}


