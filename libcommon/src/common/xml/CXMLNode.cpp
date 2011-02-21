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

#include <common/CObject.h>
#include <common/CException.h>
#include <common/data/CBuffer.h>
#include <common/xml/CXMLNode.h>

using namespace std;

CXMLNode::CXMLNode()
{
	SetParent(NULL);
}

CXMLNode::CXMLNode(const string& name)
{
	SetParent(NULL);
	SetName(name);
}

CXMLNode::~CXMLNode()
{
	try
	{
		Destroy();
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

	}
}
void CXMLNode::CopyFrom(CXMLNode* pXMLNode)
{
	Destroy();

	SetName(pXMLNode->GetName());
	SetData(pXMLNode->GetData().c_str(), pXMLNode->GetData().size());

	for(u32 i = 0 ; i < pXMLNode->GetNumAttribut() ; i += 2)
	SetAttribut(pXMLNode->GetAttribut(i), pXMLNode->GetAttribut(i + 1));

	for(u32 i = 0 ; i < pXMLNode->GetNumChild() ; i++)
	{
		CXMLNode* pCurrentChild = new CXMLNode;
		pCurrentChild->CopyFrom(pXMLNode->GetChild(i));
		PushChild(pCurrentChild);
	}
}

void CXMLNode::SetParent(CXMLNode* pParent)
{
	this->pParent = pParent;
}

CXMLNode* CXMLNode::GetParent()
{
	return pParent;
}

void CXMLNode::SetNameSpace(const string& nameSpace)
{
	SetAttribut("xmlns", nameSpace);
}

const string& CXMLNode::GetNameSpace() const
{
	return GetAttribut("xmlns");
}

void CXMLNode::PushChild(CXMLNode* pNode)
{
	try
	{
		pNode->SetParent(this);
		childVector.push_back(pNode);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_PUSHCHILDERROR);
	}
}

bool CXMLNode::IsExistChild(const string& name) const
{
	u32 index;
	return SearchChild(name, &index);
}

bool CXMLNode::IsExistAttribut(const string& attr) const
{
	u32 index;
	return SearchAttribut(attr, &index);
}

bool CXMLNode::IsExistAttribut(const string& attr, const string& value) const
{
	u32 index;
	
	if(!SearchAttribut(attr, &index))
	return false;
	
	return attrVector[index + 1] == value;
}


CXMLNode* CXMLNode::GetChild(u32 index) const
{
	try
	{
		if(index >= childVector.size())
		throw CXMLNodeException(CXMLNodeException::XNEC_GETCHILDERROR);

		return childVector[index];
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_GETCHILDERROR);
	}
}


CXMLNode* CXMLNode::GetChild(const string& name) const
{
	try
	{
		u32 index;
		
		if(!SearchChild(name, &index))
		throw CXMLNodeException(CXMLNodeException::XNEC_GETCHILDERROR);
		
		return childVector[index];
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_GETCHILDERROR);
	}
}

CXMLNode* CXMLNode::PopChild(u32 index)
{
	CXMLNode* pXMLNode = GetChild(index);
	pXMLNode->Detach();
	return pXMLNode;
}


CXMLNode* CXMLNode::PopChild(const string& name)
{
	CXMLNode* pXMLNode = GetChild(name);
	pXMLNode->Detach();
	return pXMLNode;
}

void CXMLNode::Detach()
{
	try
	{
		if(GetParent() != NULL)
		{
			pParent->Detach(this);
			SetParent(NULL);
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_DETACHERROR);
	}
}

void CXMLNode::Detach(CXMLNode* pXMLNode)
{
	try
	{
		u32 index;
				
		if(!SearchChild(pXMLNode, &index))
		throw CXMLNodeException(CXMLNodeException::XNEC_DETACHERROR);
		
		childVector.erase(childVector.begin() + index);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_DETACHERROR);
	}
}

CObject::u32 CXMLNode::GetNumChild() const
{
	return childVector.size();
}

void CXMLNode::SetName(const string& name)
{
	try
	{
		this->name = name;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_SETNAMEERROR);
	}
}

const string& CXMLNode::GetName() const
{
	return name;
}

void CXMLNode::SetData(const char data[], u32 len)
{
	try
	{
		this->data = "";
		AppendData(data, len);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_SETDATAERROR);
	}
}
void CXMLNode::AppendData(const char data[], u32 len)
{
	try
	{
		this->data.append(data, len);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_SETDATAERROR);
	}
}

const string& CXMLNode::GetData() const
{
	return data;
}

void CXMLNode::SetAttribut(const string& attr, const string& value)
{
	try
	{
		u32 index;
		
		if(SearchAttribut(attr, &index))
		{
			attrVector[index + 1] = value;
		}
		else
		{
			attrVector.push_back(attr);
			attrVector.push_back(value);
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_ADDATTRIBUTERROR);
	}
}

bool CXMLNode::SearchAttribut(const string& attr, u32* pIndex) const
{
	for(*pIndex = 0 ; *pIndex < GetNumAttribut() ; (*pIndex) += 2)
	{
		if(attrVector[*pIndex] == attr)
		return true;
	}

	return false;
}

const string& CXMLNode::GetAttribut(const string& attr) const
{
	try
	{
		u32 index = 0;
		
		if(SearchAttribut(attr, &index))
		return attrVector[index + 1];

		throw CXMLNodeException(CXMLNodeException::XNEC_GETATTRIBUTERROR);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_GETATTRIBUTERROR);
	}
}

const string& CXMLNode::GetAttribut(u32 index) const
{
	try
	{
		return attrVector[index];
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw CXMLNodeException(CXMLNodeException::XNEC_GETATTRIBUTERROR);
	}
}

CObject::u32 CXMLNode::GetNumAttribut() const
{
	return attrVector.size();
}

bool CXMLNode::SearchChild(const string& name, u32* pIndex) const
{
	for(*pIndex = 0 ; *pIndex < GetNumChild() ; (*pIndex)++)
	{
		if(childVector[*pIndex]->GetName() == name)
		return true;
	}

	return false;
}

bool CXMLNode::SearchChild(const CXMLNode* pXMLNode, u32* pIndex) const
{
	for(*pIndex = 0 ; *pIndex < GetNumChild() ; (*pIndex)++)
	{
		if(childVector[*pIndex] == pXMLNode)
		return true;
	}

	return false;
}

void CXMLNode::Build(CBuffer* pBuffer) const
{
	try
	{
		u32 size = GetXMLNodeSize();
		pBuffer->Create(size);
		BuildNode(pBuffer);
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw e;
	}

}
void CXMLNode::BuildNode(CBuffer* pBuffer) const
{
	try
	{
		pBuffer->Write("<");
		pBuffer->Write(GetName().c_str());

		for(u32 i = 0 ; i < GetNumAttribut() ; i += 2)
		{
			pBuffer->Write(" ");
			pBuffer->Write(GetAttribut(i).c_str());
			pBuffer->Write("='");
			pBuffer->Write(GetAttribut(i + 1).c_str());
			pBuffer->Write("'");
		}
		
		if(GetNumChild() == 0 && GetData().size() == 0)
		{
			pBuffer->Write("/>");
		}
		else
		{
			pBuffer->Write(">");
			pBuffer->Write(GetData().c_str());

			for(u32 i = 0 ; i < GetNumChild() ; i++)
			GetChild(i)->BuildNode(pBuffer);
		
			pBuffer->Write("</");
			pBuffer->Write(GetName().c_str());
			pBuffer->Write(">");
		}
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw e;
	}
}


CObject::u32 CXMLNode::GetXMLNodeSize() const
{
	try
	{
		u32 size = 2;
		size += GetName().size();
	
		for(u32 i = 0 ; i < GetNumAttribut() ; i += 2)
		{
			size += 4;
			size += GetAttribut(i).size();
			size += GetAttribut(i + 1).size();
		}

		if(GetNumChild() == 0 && GetData().size() == 0)
		{
			size++;
		}
		else
		{
			size += GetData().size();
		
			for(u32 i = 0 ; i < GetNumChild() ; i++)
			size += GetChild(i)->GetXMLNodeSize();

	
			size += 3;
			size += GetName().size();
		}
		
		return size;
	}
	
	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__

		throw e;
	}
}

void CXMLNode::Destroy()
{
	name = "";
	data = "";
	
	for(u32 i = 0 ; i < childVector.size() ; i++)
	delete childVector[i];

	attrVector.clear();
	childVector.clear();
}

CXMLNodeException::CXMLNodeException(int code) : CException(code)
{}

CXMLNodeException::~CXMLNodeException() throw()
{}

const char* CXMLNodeException::what() const throw()
{
	switch(GetCode())
	{
	case XNEC_SETDATAERROR:
		return "CXMLNodeException: Can not set data";

	case XNEC_SETNAMEERROR:
		return "CXMLNodeException: Can not set name";

	case XNEC_PUSHCHILDERROR:
		return "CXMLNodeException: Can not add new child";

	case XNEC_DETACHERROR:
		return "CXMLNodeException: Can not detach a child";

	case XNEC_GETCHILDERROR:
		return "CXMLNodeException: Can not get a child";

	case XNEC_ADDATTRIBUTERROR:
		return "CXMLNodeException: Can not add attribut";

	case XNEC_GETATTRIBUTERROR:
		return "CXMLNodeException: Can not get attribut";

	default:
		return "CXMLNodeException: Unknown error";
	}
}

