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

#ifndef __CCONNECTION_H__
#define __CCONNECTION_H__

#include <common/CObject.h>
#include <common/data/CBuffer.h>
#include <common/socket/CAddress.h>

class CConnection : public CObject
{
public:
	CConnection();
	virtual ~CConnection();

	virtual void Connect(const CAddress* pAddress);
	virtual void Connect(const CAddress& rAddress);
	virtual void Disconnect();
	
	virtual bool IsConnected();
	
	virtual bool Send(const CBuffer* pBuffer);
	virtual bool Receive(CBuffer* pBuffer);
};

#endif // __CCONECTION_H__
