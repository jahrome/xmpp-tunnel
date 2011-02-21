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
 
#ifndef __CXMLNODE_H__
#define __CXMLNODE_H__

#include <pthread.h>
#include <string>
#include <vector>

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>

using namespace std;

class CXMLNode : public CObject
{
public:
	CXMLNode();
	CXMLNode(const string& name);
	virtual ~CXMLNode();
	
	void CopyFrom(CXMLNode* pXMLNode);
	
	void SetParent(CXMLNode* pParent);
	CXMLNode* GetParent();

	void SetNameSpace(const string& nameSpace);
	const string& GetNameSpace() const;

	void PushChild(CXMLNode* pXMLNode);
	
	bool IsExistChild(const string& name) const;
	bool IsExistAttribut(const string& attr) const;
	bool IsExistAttribut(const string& attr, const string& value) const;
	
	CXMLNode* GetChild(u32 index) const;
	CXMLNode* GetChild(const string& name) const;

	CXMLNode* PopChild(u32 index);
	CXMLNode* PopChild(const string& name);
	
	void Detach();
	void Detach(CXMLNode* pXMLNode);

	u32 GetNumChild() const;

	const string& GetName() const;
	const string& GetData() const;

	void SetName(const string& name);
	void SetData(const char data[], u32 len);
	void AppendData(const char data[], u32 len);
	
	void SetAttribut(const string& attr, const string& value);

	const string& GetAttribut(u32 index) const;
	const string& GetAttribut(const string& attr) const;

	u32 GetNumAttribut() const;
	void Build(CBuffer* pBuffer) const;

	void Destroy();

protected:
	bool SearchChild(const string& name, u32* pIndex) const;
	bool SearchChild(const CXMLNode* pXMLNode, u32* pIndex) const;
	bool SearchAttribut(const string& attr, u32* pIndex) const;

	void BuildNode(CBuffer* pBuffer) const;
	u32 GetXMLNodeSize() const;

private:
	CXMLNode* pParent;
	vector<CXMLNode*> childVector;

	string name;
	string data;
	string nameSpaceView;
	vector<string> attrVector;
};

class CXMLNodeException : public CException
{
public:
	enum XMLNodeExceptionCode
	{
		XNEC_SETNAMEERROR,
		XNEC_SETDATAERROR,
		XNEC_PUSHCHILDERROR,
		XNEC_DETACHERROR,
		XNEC_GETCHILDERROR,
		XNEC_ADDATTRIBUTERROR,
		XNEC_GETATTRIBUTERROR
	};

public:
	CXMLNodeException(int code);
	virtual ~CXMLNodeException() throw();

	virtual const char* what() const throw();
};

#endif //__CXMLNODE_H__
