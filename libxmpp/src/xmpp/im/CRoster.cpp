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
#include <string>

#include <common/CObject.h>
#include <common/CException.h>

#include <xmpp/im/CRoster.h>
#include <xmpp/im/CRosterItem.h>
#include <xmpp/jid/CJid.h>

using namespace std;

CRoster::CRoster()
{
}

CRoster::~CRoster()
{
}

void CRoster::UpdateItem(const CRosterItem& rRosterItem)
{
	for(u32 i = 0 ; i < GetNumItem() ; i++)
	{
		if(RosterItemList[i].GetJid().GetShort() == rRosterItem.GetJid().GetShort())
		{
			RosterItemList[i] = rRosterItem;
			return;
		}
	}
	
	RosterItemList.insert(RosterItemList.begin(), rRosterItem);
}

CObject::u32 CRoster::GetNumItem() const
{
	return RosterItemList.size();
}

const CRosterItem& CRoster::GetItem(u32 index) const
{
	return RosterItemList[index];
}

const CRosterItem& CRoster::GetItem(const CJid& rJid) const
{
	for(u32 i = 0 ; i < GetNumItem() ; i++)
	{
		if(RosterItemList[i].GetJid() == rJid)
		return RosterItemList[i];
	}
	
	throw CRosterException(CRosterException::REC_GETITEMERROR);
}


CRosterException::CRosterException(int code) : CException(code)
{}

CRosterException::~CRosterException() throw()
{}
	
const char* CRosterException::what() const throw()
{
	switch(GetCode())
	{
	case REC_CONSTRUCTORERROR:
		return "CRoster::Constructor() error";
	
	case REC_UPDATEITEMERROR:
		return "CRoster::UpdateItem() error";

	case REC_GETITEMERROR:
		return "CRoster::GetItem() error";

	case REC_GETNUMITEMERROR:
		return "CRoster::GetNumItem() error";

	default:
		return "CRoster: Unknown error";
	}
}
