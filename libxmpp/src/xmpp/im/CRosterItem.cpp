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

#include <xmpp/im/CRosterItem.h>
#include <xmpp/jid/CJid.h>

using namespace std;

CRosterItem::CRosterItem()
{
	isAvailable = false;
}

CRosterItem::CRosterItem(const CRosterItem& rRosterItem)
{
	isAvailable = false;
	Affect(rRosterItem);
}

CRosterItem::~CRosterItem()
{
}

void CRosterItem::Affect(const CRosterItem& rRosterItem)
{
	SetJid(rRosterItem.GetJid());
	SetShow(rRosterItem.GetShow());
	SetStatus(rRosterItem.GetStatus());
	
	if(rRosterItem.IsAvailable())
	SetAvailable();
	else
	SetUnavailable();
	
}

bool CRosterItem::IsEqual(const CRosterItem& rRosterItem) const
{
	return GetJid() == rRosterItem.GetJid();
}

void CRosterItem::operator=(const CRosterItem& rRosterItem)
{
	Affect(rRosterItem);
}

bool CRosterItem::operator==(const CRosterItem& rRosterItem) const
{
	return IsEqual(rRosterItem);
}


void CRosterItem::SetJid(const CJid& rJid)
{
	Jid = rJid;
}

void CRosterItem::SetShow(const string& show)
{
	this->show = show;
}

void CRosterItem::SetStatus(const string& status)
{
	this->status = status;
}

void CRosterItem::SetAvailable()
{
	isAvailable = true;
}

void CRosterItem::SetUnavailable()
{
	isAvailable = false;
}


const CJid& CRosterItem::GetJid() const
{
	return Jid;
}

const string& CRosterItem::GetShow() const
{
	return show;
}

const string& CRosterItem::GetStatus() const
{
	return status;
}

bool CRosterItem::IsAvailable() const
{
	return isAvailable;
}



CRosterItemException::CRosterItemException(int code) : CException(code)
{}

CRosterItemException::~CRosterItemException() throw()
{}
	
const char* CRosterItemException::what() const throw()
{
	switch(GetCode())
	{
	case RIEC_CONSTRUCTORERROR:
		return "CRosterItem::Constructor() error";

	default:
		return "CRosterItem: Unknown error";
	}
}
