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

#ifndef __CSSHCONFIG_H__
#define __CSSHCONFIG_H__

#include <iostream>
#include <string>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/crypto/rsa/CRsaKey.h>
#include <common/socket/tcp/CTCPAddress.h>
#include <common/xml/CXMLNode.h>

#include "xmpp/jid/CJid.h"

using namespace std;

class CSSHConfig : public CObject
{
public:
	enum KeyStatus
	{
		KS_KNOWN,
		KS_UNKNOWN,
		KS_CHANGED
	};

	CSSHConfig();
	virtual ~CSSHConfig();
 	
	void Interactive(const string& fileName);
	void Save(const string& fileName);

	const CJid& GetJid(){return Jid;}
	const CTCPAddress& GetHostAddress(){return HostAddress;}

	void AddPubKey(const CJid& rJid, const CRsaKey& rRsaKey);
	KeyStatus IsExistPubKey(const CJid& rJid, const CRsaKey& rRsaKey);

protected:
	void Load(const string& fileName);

	void RequestPassword(const string& message, string& password);
	void RequestString(const string& message, string& string);
	
	u32 GetFileSize(const string& fileName);
	bool IsFileExists(const string& fileName);

private:
	void BuildMissing();
	void CheckForHostSetting(const string& password);

private:
	CXMLNode ConfigNode;
	CRsaKey RsaKey;
	CJid Jid;
	CTCPAddress HostAddress;
};

class CSSHConfigException : public CException
{
public:
	enum SSHConfigExceptionCode
	{
		SSHDCEC_LOADERROR,
		SSHDCEC_SAVEERROR,
		SSHDCEC_ISFILEEXISTSERROR,
		SSHDCEC_GETFILESIZEERROR,
		SSHDCEC_INTERACTIVEERROR
	};

public:
	CSSHConfigException(int code);
	virtual ~CSSHConfigException() throw();

	virtual const char* what() const throw();
};

#endif //__CSSHDCONFIG_H__
