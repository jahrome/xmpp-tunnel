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

#ifndef __CROSTER_H__
#define __CROSTER_H__

#include <string>
#include <vector>

#include <common/CObject.h>
#include <common/CException.h>

#include <xmpp/im/CRosterItem.h>
#include <xmpp/jid/CJid.h>


using namespace std;

class CRoster : public CObject
{
public:
	CRoster();
	virtual ~CRoster();
	
	void UpdateItem(const CRosterItem& rRosterItem);
	
	u32 GetNumItem() const;
	const CRosterItem& GetItem(u32 index) const;
	const CRosterItem& GetItem(const CJid& rJid) const;

protected:

private:
	vector<CRosterItem> RosterItemList;
};

class CRosterException : public CException
{
public:
	enum RosterExceptionCode
	{
		REC_CONSTRUCTORERROR,
		REC_GETITEMERROR,
		REC_UPDATEITEMERROR,
		REC_GETNUMITEMERROR
	};

public:
	CRosterException(int code);
	virtual ~CRosterException() throw();

	virtual const char* what() const throw();
};
 
#endif // __CROSTER_H__
