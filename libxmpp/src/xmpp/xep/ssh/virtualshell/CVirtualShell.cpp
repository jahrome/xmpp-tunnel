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

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <common/CException.h>
#include <common/CObject.h>
#include <common/data/CBuffer.h>

#include <xmpp/xep/ssh/virtualshell/CVirtualShell.h>

CVirtualShell::CVirtualShell()
{
	fdMaster = -1;
	shellPid = -1;
	slavePath = NULL;
}

CVirtualShell::CVirtualShell(u32 uid, u32 gid, const string& defaultShell, const string& homePath, uInt32 maxBufferSize)
{
	fdMaster = -1;
	shellPid = -1;
	slavePath = NULL;

	Create(uid, gid, defaultShell, homePath, maxBufferSize);
}

CVirtualShell::~CVirtualShell()
{
	Destroy();
}

bool CVirtualShell::Create(u32 uid, u32 gid, const string& defaultShell, const string& homePath, uInt32 maxBufferSize)
{
	signal(SIGCHLD, SIG_IGN);

	if(fdMaster != -1 || shellPid != -1)
	return 1;
	
	this->maxBufferSize = maxBufferSize;
	fdMaster = OpenMaster();

	if(fdMaster < 0)
	return 0;

	if(grantpt(fdMaster) < 0 || unlockpt(fdMaster) < 0)
	{
		close(fdMaster);
		return 0;
	}

	shellPid = fork();

	if(shellPid < 0)
	{
		close(fdMaster);
		return 0;
	}
	
	if(shellPid == 0)
	{
		setsid();
		
		ioctl(fdMaster, TIOCSCTTY, NULL);
		slavePath = ptsname(fdMaster);
		int fdSlave = open(slavePath, O_RDWR);

		if(fdSlave < 0)
		_exit(0);

		dup2(fdSlave, 0);
		dup2(fdSlave, 1);
		dup2(fdSlave, 2);

		close(fdSlave);

		char promptBehavior[200];
				
		sprintf(promptBehavior, "\\u@\\H\\$ ");
		setenv("PS1", promptBehavior, 1);
		setenv("HOME", homePath.c_str(), 1);
		setenv("DISPLAY", "unix:1.0", 1);

		chdir(homePath.c_str());

		setuid(uid);
		setgid(gid);

		execlp(defaultShell.c_str(), "-", NULL);
		_exit(1);
	}

	return 1;
}

void CVirtualShell::Destroy()
{
	if(fdMaster == -1 || shellPid == -1)
	return;

	unlink(slavePath);
	kill(shellPid, SIGKILL);
	close(fdMaster);
	
	fdMaster = -1;
	shellPid = -1;
	slavePath = NULL;
}

bool CVirtualShell::SetShellSize(int row, int col, int xpixel, int ypixel)
{
	if(fdMaster == -1 || shellPid == -1)
	return false;

	struct winsize w;

	w.ws_row = row;
	w.ws_col = col;
    w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;

	return ioctl(fdMaster, TIOCSWINSZ, &w) == 0;
}

int CVirtualShell::OpenMaster()
{int fdMaster;
	// Trying to open /dev/ptmx
	/*	
	int fdMaster = open("/dev/ptmx", O_RDWR);

	cout << "PTMX:" << fdMaster << endl;
	if(fdMaster > 0)
	return fdMaster;
	cout << "PTMX ERROR" << endl;
	*/	
	char pty[11];
	// Trying to open ptyXY with X = [p-sP-S] and Y = [a-z0-9]
	
	char xStart = 'p', xStop = 's';

	while(xStart <= xStop)
	{
		char yStart = 'a', yStop = 'z';

		while(yStart <= yStop)
		{
			sprintf(pty, "/dev/pty%c%c", xStart, yStart);

			fdMaster = open(pty, O_RDWR | O_NOCTTY);

			if(fdMaster >= 0)
			return fdMaster;

			yStart++;
			
			if(yStart > yStop && yStop == 'z')
			{
				yStart = '0';
				yStop  = '9';			
			}
		}
		
		xStart++;
		
		if(xStart > xStop && xStop == 's')
		{
			xStart = 'P';
			xStop  = 'S';
		}		
	}

	return -1;
}

bool CVirtualShell::Write(const CBuffer* pBuffer)
{
	if(fdMaster == -1 || shellPid == -1)
	return false;

	uByte* buffer        = pBuffer->GetBuffer();
	uInt32 dataSize      = pBuffer->GetBufferSize();
	uInt32 totalDataSize = 0;

	while(dataSize > totalDataSize)
	{
		int currentDataSize = write(fdMaster, buffer + totalDataSize, dataSize - totalDataSize);

		if(currentDataSize <= 0)
		return false;

		totalDataSize += currentDataSize;
	}

	return true;
}

bool CVirtualShell::Read(CBuffer* pBuffer)
{
	if(fdMaster == -1 || shellPid == -1)
	return false;

	uByte* buffer = new uByte[maxBufferSize];
	
	if(buffer == NULL)
	return false;
	
	int dataSize = read(fdMaster, buffer, maxBufferSize);

	if(dataSize <= 0)
	{
		delete[] buffer;
		return false;
	}

	if(!pBuffer->Create((u32) dataSize))
	{
		delete[] buffer;
		return false;
	}
	
	pBuffer->Write(buffer, dataSize);

	delete[] buffer;
	return true;
}
