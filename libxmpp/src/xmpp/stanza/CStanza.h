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

#ifndef __CSTANZA_H__
#define __CSTANZA_H__

#include <string>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

using namespace std;

class CStanza : public CObject
{
public:
	enum StanzaKindOf
	{
		SKO_UNKNOWN,
		SKO_OPEN,
		SKO_FEATURES,
		SKO_PROCEED,
		SKO_STARTTLS,
		SKO_IQ,
		SKO_MESSAGE,
		SKO_PRESENCE,
		SKO_CLOSE,
		SKO_SUCCESS,
		SKO_AUTH,
		SKO_CHALLENGE,
		SKO_RESPONSE
	};

	CStanza();
	virtual ~CStanza();

	CXMLNode* DetachXMLNode();
	CXMLNode* GetXMLNode() const;
	void AttachXMLNode(CXMLNode* pXMLNode);
	
	u32 GetKindOf() const;
	virtual void Build(CBuffer* pBuffer) const;

	const string& GetNameSpace() const;
	const string& GetName() const;
	const string& GetTo() const;
	const string& GetFrom() const;
	const string& GetId() const;
	const string& GetType() const;
	const string& GetLang() const;
	
	void SetNameSpace(const string& nameSpace);
	void SetName(const string& name);
	void SetTo(const string& to);
	void SetType(const string& type);
	void SetLang(const string& lang);
	void SetId(const string& id);


	void SetData(const char data[], u32 len);
	void AppendData(const char data[], u32 len);
	const string& GetData() const;
	
	void SetAttribut(const string& attr, const string& value);
	const string& GetAttribut(const string& attr) const;

	void PushChild(CXMLNode* pXMLNode);
	
	bool IsExistChild(const string& name) const;
	bool IsExistAttribut(const string& attr) const;
	
	CXMLNode* GetChild(u32 index) const;
	CXMLNode* GetChild(const string& name) const;

	CXMLNode* PopChild(u32 index);
	CXMLNode* PopChild(const string& name);

private:
	CXMLNode* pXMLNode;
};
 
class CStanzaException : public CException
{
public:
	enum StanzaExceptionCode
	{
		SEC_CONSTRUCTORERROR,
		SEC_DESTRUCTORERROR,		
		SEC_DETACHXMLNODEERROR,
		SEC_GETXMLNODEERROR,
		SEC_ATTACHXMLNODEERROR,
		SEC_GETKINDOFERROR,
		SEC_BUILDERROR,
		SEC_SETTOERROR,
		SEC_SETNAMEERROR,
		SEC_SETNAMESPACEERROR,
		SEC_SETIDERROR,
		SEC_SETATTRIBUTERROR,
		SEC_SETTYPEERROR,
		SEC_SETLANGERROR,
		SEC_SETDATAERROR,
		SEC_APPENDDATAERROR,
		SEC_GETATTRIBUTERROR,
		SEC_GETTOERROR,
		SEC_GETNAMEERROR,
		SEC_GETNAMESPACEERROR,
		SEC_GETFROMERROR,
		SEC_GETIDERROR,
		SEC_GETTYPEERROR,
		SEC_GETLANGERROR,
		SEC_GETDATAERROR,
		SEC_PUSHCHILDERROR,
		SEC_ISEXISTCHILDERROR,
		SEC_ISEXISTATTRIBUTERROR,
		SEC_POPCHILDERROR,
		SEC_GETCHILDERROR
	};

public:
	CStanzaException(int code);
	virtual ~CStanzaException() throw();

	virtual const char* what() const throw();
};
	
#endif // __CSTANZA_H__
