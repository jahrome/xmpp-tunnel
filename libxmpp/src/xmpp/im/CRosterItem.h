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

#ifndef __CROSTERITEM_H__
#define __CROSTERITEM_H__

#include <string>
#include <vector>

#include <common/CObject.h>
#include <common/CException.h>

#include <xmpp/jid/CJid.h>

using namespace std;

class CRosterItem : public CObject
{
public:
	CRosterItem();
	CRosterItem(const CRosterItem& rRosterItem);
	virtual ~CRosterItem();

	void Affect(const CRosterItem& rRosterItem);
	bool IsEqual(const CRosterItem& rRosterItem) const;

	void operator=(const CRosterItem& rRosterItem);
	bool operator==(const CRosterItem& rRosterItem) const;


	void SetJid(const CJid& rJid);
	void SetShow(const string& show);
	void SetStatus(const string& status);
	void SetAvailable();
	void SetUnavailable();

	const CJid& GetJid() const;
	const string& GetShow() const;
	const string& GetStatus() const;
	bool IsAvailable() const;

private:
	CJid Jid;
	string show;
	string status;
	bool isAvailable;
};

class CRosterItemException : public CException
{
public:
	enum RosterItemExceptionCode
	{
		RIEC_CONSTRUCTORERROR
	};

public:
	CRosterItemException(int code);
	virtual ~CRosterItemException() throw();

	virtual const char* what() const throw();
};
 
#endif // __CROSTERITEM_H__
