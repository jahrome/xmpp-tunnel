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

#ifndef __CCHANNELCLOSEHANDLER_H__
#define __CCHANNELCLOSEHANDLER_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/core/CHandler.h>

using namespace std;

class CChannelCloseHandler : public CHandler
{
public:
	CChannelCloseHandler();	
	virtual ~CChannelCloseHandler();
};
 
class CChannelCloseHandlerException : public CException
{
public:
	enum ChannelCloseHandlerExceptionCode
	{
		CCHEC_CONSTRUCTORERROR
	};

public:
	CChannelCloseHandlerException(int code);
	virtual ~CChannelCloseHandlerException() throw();

	virtual const char* what() const throw();
};

#endif // __CCHANNELCLOSEHANDLER_H__
