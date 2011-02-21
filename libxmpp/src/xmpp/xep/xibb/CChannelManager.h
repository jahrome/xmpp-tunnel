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
 
#ifndef __CCHANNELMANAGER_H__
#define __CCHANNELMANAGER_H__

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/xep/xibb/CChannel.h>

using namespace std;

class CChannelManager : public CObject
{
public:
	CChannelManager(const CJid& remoteJid, u16 maxChannel);
	virtual ~CChannelManager();
	
	const CJid& GetRemoteJid() const;
	u16 GetMaxChannel() const;

	u16 AddChannel(CChannel* pChannel);

	CChannel* GetChannelByLocalCid(u16 localCid);
	CChannel* GetChannelByRemoteCid(u16 remoteCid);

	void RemoveChannelByLocalCid(u16 localCid);
	void RemoveChannelByRemoteCid(u16 remoteCid);

private:			
	vector<CChannel*> ChannelList;
	CJid RemoteJid;
};
 
class CChannelManagerException : public CException
{
public:
	enum ChannelManagerExceptionCode
	{
		CMEC_CONSTRUCTORERROR,
		CMEC_DESTRUCTORERROR,
		CMEC_ADDCHANNELERROR,
		CMEC_GETCHANNELBYLOCALCIDERROR,
		CMEC_GETCHANNELBYREMOTECIDERROR,
		CMEC_REMOVECHANNELBYLOCALCIDERROR,
		CMEC_REMOVECHANNELBYREMOTECIDERROR
	};

public:
	CChannelManagerException(int code);
	virtual ~CChannelManagerException() throw();

	virtual const char* what() const throw();
};

#endif // __CCHANNELMANAGER_H__
