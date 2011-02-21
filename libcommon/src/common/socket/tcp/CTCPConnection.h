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

#ifndef __CTCPCONNECTION_H__
#define __CTCPCONNECTION_H__

#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/socket/CConnection.h>
#include <common/socket/tcp/CTCPAddress.h>

class CTCPConnection : public CConnection
{
public:
	CTCPConnection();
	CTCPConnection(CTCPAddress* pTCPAddress);
	CTCPConnection(CTCPAddress& rTCPAddress);
	virtual ~CTCPConnection();

	void SetTCPAddress(const CTCPAddress* pTCPAddress);
	void SetTCPAddress(const CTCPAddress& rTCPAddress);
	const CTCPAddress& GetTCPAddress() const;
	
	void Connect();
	void Connect(const CTCPAddress& rTCPAddress);
	void Connect(const CTCPAddress* pTCPAddress);
	void Disconnect();
	
	bool Send(const CBuffer* pBuffer);
	bool Receive(CBuffer* pBuffer);

	bool IsConnected() const;

private:
	CTCPAddress TCPAddress;
	bool isConnected;
};

class CTCPConnectionException : public CException
{
public:
	enum TCPConnectionExceptionCode
	{
		TCPCEC_CONSTRUCTORERROR,
		TCPCEC_DESTRUCTORERROR,
		TCPCEC_SETTCPADDRESSERROR,
		TCPCEC_SENDERROR,
		TCPCEC_RECEIVEERROR,
		TCPCEC_CONNECTERROR,
		TCPCEC_DISCONNECTERROR
	};

public:
	CTCPConnectionException(int code);
	virtual ~CTCPConnectionException() throw();

	virtual const char* what();
};

#endif // __CTCPCONNECTION_H__
