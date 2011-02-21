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

#ifndef __CVIRTUALSHELL_H__
#define __CVIRTUALSHELL_H__

#include <sys/types.h> // uid_t, gid_t

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>

class CVirtualShell : public CObject
{
public:
	CVirtualShell();
	CVirtualShell(u32 uid, u32 gid, const string& defaultShell, const string& homePath, uInt32 maxBufferSize = 1024);
	virtual ~CVirtualShell();

	bool Create(u32 uid, u32 gid, const string& defaultShell, const string& homePath, uInt32 maxBufferSize = 1024);
	void Destroy();

	bool Write(const CBuffer* pBuffer);
	bool Read(CBuffer* pBuffer);

	bool SetShellSize(int row, int col, int xpixel, int ypixel);

protected:
	static int OpenMaster();

private:
	char* slavePath;
	int fdMaster;
	int shellPid;
	uInt32 maxBufferSize;
};

#endif // __CVIRTUALSHELL_H__
