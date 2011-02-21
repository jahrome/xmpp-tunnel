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

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <time.h>

#include <string>
#include <vector>

#include <common/CException.h>
#include <common/CObject.h>

#include <xmpp/jid/CJid.h>
#include <xmpp/xep/xibb/CChannel.h>
#include <xmpp/xep/xibb/CChannelManager.h>

using namespace std;

CChannelManager::CChannelManager(const CJid& rRemoteJid, u16 maxChannel)
{
	try
	{
		RemoteJid = rRemoteJid;
		ChannelList.resize(maxChannel);
		
		for(u16 i = 0 ; i < ChannelList.size() ; i++)
		ChannelList[i] = NULL;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelManagerException(CChannelManagerException::CMEC_CONSTRUCTORERROR);
	}
}

CChannelManager::~CChannelManager()
{
	try
	{
		for(u16 i = 0 ; i < ChannelList.size() ; i++)
		{
			if(ChannelList[i] != NULL)
			delete ChannelList[i];
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}

const CJid& CChannelManager::GetRemoteJid() const
{
	return RemoteJid;
}

CObject::u16 CChannelManager::GetMaxChannel() const
{
	return ChannelList.size();
}

CObject::u16 CChannelManager::AddChannel(CChannel* pChannel)
{
	try
	{
		for(u16 i = 0 ; i < ChannelList.size() ; i++)
		{
			if(ChannelList[i] == NULL)
			{
				ChannelList[i] = pChannel;
				return i;
			}
		}
		
		throw CChannelManagerException(CChannelManagerException::CMEC_ADDCHANNELERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelManagerException(CChannelManagerException::CMEC_ADDCHANNELERROR);
	}	
}

CChannel* CChannelManager::GetChannelByLocalCid(u16 localCid)
{
	try
	{
		return ChannelList[localCid];
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelManagerException(CChannelManagerException::CMEC_GETCHANNELBYLOCALCIDERROR);
	}
}

CChannel* CChannelManager::GetChannelByRemoteCid(u16 remoteCid)
{
	try
	{
		for(u16 i = 0 ; i < ChannelList.size() ; i++)
		{
			if(ChannelList[i] != NULL)
			{
				if(ChannelList[i]->GetRemoteCid() == remoteCid)
				return ChannelList[i];
			}
		}
		
		return NULL;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelManagerException(CChannelManagerException::CMEC_GETCHANNELBYREMOTECIDERROR);
	}	
}

void CChannelManager::RemoveChannelByLocalCid(u16 localCid)
{
	try
	{
		if(ChannelList[localCid] != NULL)
		{
			delete ChannelList[localCid];
			ChannelList[localCid] = NULL;
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelManagerException(CChannelManagerException::CMEC_REMOVECHANNELBYLOCALCIDERROR);
	}	
}

void CChannelManager::RemoveChannelByRemoteCid(u16 remoteCid)
{
	try
	{
		for(u16 i = 0 ; i < ChannelList.size() ; i++)
		{
			if(ChannelList[i] != NULL)
			{
				if(ChannelList[i]->GetRemoteCid() == remoteCid)
				{
					delete ChannelList[i];
					ChannelList[i] = NULL;
					return;
				}
			}
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CChannelManagerException(CChannelManagerException::CMEC_REMOVECHANNELBYREMOTECIDERROR);
	}	
}


CChannelManagerException::CChannelManagerException(int code) : CException(code)
{}

CChannelManagerException::~CChannelManagerException() throw()
{}
	
const char* CChannelManagerException::what() const throw()
{
	switch(GetCode())
	{
	case CMEC_CONSTRUCTORERROR:
		return "CChannelManager::Constructor() error";
		
	case CMEC_DESTRUCTORERROR:
		return "CChannelManager::Destructor() error";

	case CMEC_ADDCHANNELERROR:
		return "CChannelManager::AddChannel() error";
		
	case CMEC_GETCHANNELBYLOCALCIDERROR:
		return "CChannelManager::GetChannelByLocalCid() error";

	case CMEC_GETCHANNELBYREMOTECIDERROR:
		return "CChannelManager::GetChannelByRemoteCid() error";

	case CMEC_REMOVECHANNELBYLOCALCIDERROR:
		return "CChannelManager::RemoveChannelByLocalCid() error";

	case CMEC_REMOVECHANNELBYREMOTECIDERROR:
		return "CChannelManager::RemoveChannelByRemoteCid() error";

	default:
		return "CChannelManager: Unknown error";
	}
}
