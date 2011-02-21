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

#ifndef __CTLSCONNECTION_H__
#define __CTLSCONNECTION_H__

#include <openssl/ssl.h>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>
#include <common/socket/tcp/CTCPAddress.h>
#include <common/socket/tcp/CTCPConnection.h>

class CTLSConnection : public CTCPConnection
{
public:
	CTLSConnection();
	CTLSConnection(CTCPAddress* pTCPAddress);
	CTLSConnection(CTCPAddress& rTCPAddress);
	virtual ~CTLSConnection();
	
	void Unsecure();
	void Secure();
	
	bool IsSecured();
	bool IsNotSecured();

	bool Send(const CBuffer* pBuffer);
	bool Receive(CBuffer* pBuffer);

private:
	bool isSecured;
	SSL* ssl;
};

class CTLSConnectionException : public CException
{
public:
	enum TLSConnectionExceptionCode
	{
		TLSCEC_SECUREERROR,
		TLSCEC_UNSECUREERROR,
		TLSCEC_SENDERROR,
		TLSCEC_RECEIVEERROR
	};

public:
	CTLSConnectionException(int code);
	virtual ~CTLSConnectionException() throw();

	virtual const char* what() const throw();
};


#endif // __CTLSCONNECTION_H__
