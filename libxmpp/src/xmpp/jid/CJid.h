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

#ifndef __CJID_H__
#define __CJID_H__

#include <string>

#include <common/CObject.h>
#include <common/CException.h>

using namespace std;

class CJid : public CObject
{
public:
	CJid();
	CJid(const CJid& rJid);
	CJid(const CJid* pJid);
	CJid(const string& jid);
	virtual ~CJid();

public:
	void SetFull(const string& jid);
	const string& GetFull() const;
	const string& GetShort() const;

	void operator = (const CJid& rJid);
	void operator = (const CJid* pJid);
	void operator = (const string& jid);

	bool operator == (const CJid& rJid) const;
	bool operator == (const CJid* pJid) const;
	bool operator == (const string& jid) const;

	void SetName(const string& name);
	void SetHost(const string& host);
	void SetResource(const string& resource);
	void SetPassword(const string& password);
	void SetShow(const string& show);
	void SetStatus(const string& status);

	const string& GetName() const;
	const string& GetHost() const;
	const string& GetResource() const;
	const string& GetPassword() const;
	const string& GetShow() const;
	const string& GetStatus() const;
	
private:
	string name;
	string host;
	string resource;
	string password;
	string jid;
	string shorter;
	
	string show;
	string status;
	
	const string CONST_STRING_EMPTY;
};

class CJidException : public CException
{
public:
	enum JidExceptionCode
	{
		JEC_CONSTRUCTORERROR,
		JEC_OPERATOREQUALERROR,
		JEC_OPERATORDOUBLEEQUALERROR,
		JEC_SETJIDERROR,
		JEC_SETNAMEERROR,
		JEC_SETHOSTERROR,
		JEC_SETRESOURCEERROR,
		JEC_SETPASSWORDERROR,
		JEC_SETSHOWERROR,
		JEC_SETSTATUSERROR
	};

public:
	CJidException(int code);
	virtual ~CJidException() throw();

	virtual const char* what() const throw();
};
 
#endif // __CJID_H__
