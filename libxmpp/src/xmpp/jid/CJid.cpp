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

#include <xmpp/jid/CJid.h>

using namespace std;

CJid::CJid()
{
}

CJid::CJid(const CJid& rJid)
{
	try
	{
		*this = rJid;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_CONSTRUCTORERROR);
	}
}

CJid::CJid(const CJid* pJid)
{
	try
	{
		*this = pJid;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_CONSTRUCTORERROR);
	}
}

CJid::CJid(const string& jid)
{
	try
	{
		*this = jid;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_CONSTRUCTORERROR);
	}
}

CJid::~CJid()
{
}

void CJid::SetFull(const string& jid)
{
	try
	{
		this->jid = jid;

		u32 atPos = jid.find("@", 0);
		u32 resPos = jid.find("/", atPos + 1);

		if(atPos == string::npos)
		return;

		SetName(jid.substr(0, atPos));
		
		if(resPos == string::npos)
		{
			SetHost(jid.substr(atPos + 1, jid.size() - atPos));
		}
		else
		{
			SetHost(jid.substr(atPos + 1, resPos - atPos - 1));
			SetResource(jid.substr(resPos + 1, jid.size() - resPos));
		}
		
		shorter = name + "@" + host;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_SETJIDERROR);
	}
}

const string& CJid::GetFull() const 
{
	return jid;
}

const string& CJid::GetShort() const
{
	return shorter;
}

void CJid::operator = (const CJid& rJid)
{
	try
	{
		*this = &rJid;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_OPERATOREQUALERROR);
	}
}

void CJid::operator = (const CJid* pJid)
{
	try
	{
		SetFull(pJid->GetFull());
		SetPassword(pJid->GetPassword());
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_OPERATOREQUALERROR);
	}
}

void CJid::operator = (const string& jid)
{
	try
	{
		SetFull(jid);
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_OPERATOREQUALERROR);
	}
}

bool CJid::operator == (const CJid& rJid) const
{
	try
	{
		return GetFull() == rJid.GetFull();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_OPERATORDOUBLEEQUALERROR);
	}
}

bool CJid::operator == (const CJid* pJid) const
{
	try
	{
		return GetFull() == pJid->GetFull();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_OPERATORDOUBLEEQUALERROR);
	}
}

bool CJid::operator == (const string& jid) const
{
	try
	{
		return GetFull() == jid;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_OPERATORDOUBLEEQUALERROR);
	}
}

void CJid::SetName(const string& name)
{
	try
	{
		this->name = name;

		jid = name + "@" + host;

		if(!resource.empty()) 
		jid += "/" + resource;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_SETNAMEERROR);
	}
}

void CJid::SetHost(const string& host)
{
	try
	{
		this->host = host;

		jid = name + "@" + host;

		if(!resource.empty()) 
		jid += "/" + resource;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_SETHOSTERROR);
	}
}

void CJid::SetResource(const string& resource)
{
	try
	{
		this->resource = resource;

		jid = name + "@" + host;

		if(!resource.empty()) 
		jid += "/" + resource;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_SETRESOURCEERROR);
	}
}

void CJid::SetPassword(const string& password)
{
	try
	{
		this->password = password;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_SETPASSWORDERROR);
	}
}

void CJid::SetShow(const string& show)
{
	try
	{
		this->show = show;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_SETSHOWERROR);
	}
}

void CJid::SetStatus(const string& status)
{
	try
	{
		this->status = status;
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CJidException(CJidException::JEC_SETSTATUSERROR);
	}
}

const string& CJid::GetName() const
{
	return name;
}

const string& CJid::GetHost() const
{
	return host;
}

const string& CJid::GetResource() const
{
	return resource;
}

const string& CJid::GetPassword() const
{
	return password;
}

const string& CJid::GetShow() const
{
	return show;
}

const string& CJid::GetStatus() const
{
	return status;
}


CJidException::CJidException(int code) : CException(code)
{}

CJidException::~CJidException() throw()
{}
	
const char* CJidException::what() const throw()
{
	switch(GetCode())
	{
	case JEC_CONSTRUCTORERROR:
		return "CJid::Constructor() error";

	case JEC_OPERATOREQUALERROR:
		return "CJid::operator=() error";

	case JEC_OPERATORDOUBLEEQUALERROR:
		return "CJid::operator==() error";

	case JEC_SETJIDERROR:
		return "CJid::SetJid() error";
		
	case JEC_SETNAMEERROR:
		return "CJid::SetName() error";
		
	case JEC_SETHOSTERROR:
		return "CJid::SetHost() error";
		
	case JEC_SETRESOURCEERROR:
		return "CJid::SetResource() error";
		
	case JEC_SETPASSWORDERROR:
		return "CJid::SetPassword() error";

	case JEC_SETSHOWERROR:
		return "CJid::SetShow() error";

	case JEC_SETSTATUSERROR:
		return "CJid::SetStatus() error";
		
	default:
		return "CJid: Unknown error";
	}
}
