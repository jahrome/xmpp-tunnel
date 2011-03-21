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

#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <termios.h>
#include <curses.h>

#include <CInterface.h>

#include <common/CObject.h>
#include <common/CException.h>

#include <resox/CResox.h>

#include <xmpp/im/CRoster.h>
#include <xmpp/jid/CJid.h>

using namespace std;

CInterface::CInterface(CResox* pResox)
{
	this->pResox = pResox;
}

CInterface::~CInterface()
{
	try
	{
	}

	catch(exception& e)
	{
		#ifdef __DEBUG__
		cerr << e.what() << endl;
		#endif //__DEBUG__
	}
}

const CJid& CInterface::SelectHost()
{
	int h, w;
	sleep(0.5);
	pMainWin = initscr();
	curs_set(0);
	noecho();
	keypad(stdscr,TRUE);
	pWinHostList = newwin(10,60,0,0);
	getmaxyx(pMainWin, h, w);
	wrefresh(pMainWin);
	move(0,0);
	
	pResox->StartRosterEvent(&Roster);
	ThreadDisplayHostJob.Run(DisplayHostJob, this);

	u32 index = 0;

	int key;
	do
	{
		MutexOnDisplay.Lock();
		mvwprintw(pWinHostList, index + 2, 0, "#");
		wrefresh(pMainWin);
		wrefresh(pWinHostList);	
		MutexOnDisplay.UnLock();

		key = getch();

		MutexOnDisplay.Lock();
		mvwprintw(pWinHostList, index + 2, 0, " ");
		MutexOnDisplay.UnLock();
		
		if(key == KEY_UP)
		{
			if(index == 0)
			index = Roster.GetNumItem() - 1;
			else
			index--;
		}

		if(key == KEY_DOWN)
		{
			if(index == Roster.GetNumItem() - 1)
			index = 0;
			else
			index++;
		}
		
		if(key == 'c')
		{
			Jid = Roster.GetItem(index).GetJid();
			pResox->StopRosterEvent();	
			endwin();
			ThreadDisplayHostJob.Wait();
			return Jid;
		}
	}
	while(key != 'q');

	pResox->StopRosterEvent();	
	ThreadDisplayHostJob.Wait();
	endwin();
	throw "";
}

void CInterface::RequestPassword(const string& message, string& password)
{
	termios old_tty;
	termios new_tty;
	
	tcgetattr(0, &old_tty);
	memcpy(&new_tty, &old_tty, sizeof(termios));

	new_tty.c_lflag &= ~(ICANON | ECHO);
	new_tty.c_cc[VMIN] = 1;

	tcsetattr(0, TCSANOW, &new_tty);
	RequestString(message, password);	
	tcsetattr(0, TCSANOW, &old_tty);
	
	cout << endl;
}

void CInterface::RequestString(const string& message, string& string)
{
	cout << message << flush;

	char str[400];

	fgets(str, 400, stdin);
	str[strlen(str) - 1] = 0;
	string = str;
}



void* CInterface::DisplayHostJob(void* pvThis) throw()
{
	CInterface* pInterface = (CInterface*) pvThis;
		
	do
	{
		pInterface->MutexOnDisplay.Lock();
		move(0, 0);
		mvwprintw(pInterface->pWinHostList, 0, 0, "----------------- [Roster List  (%d)] -----------------\n", pInterface->Roster.GetNumItem());
		mvwprintw(pInterface->pWinHostList, 1, 0, "To select a Jid use up and down key. To login press 'c' key\n");
		wrefresh(pInterface->pMainWin);
		wrefresh(pInterface->pWinHostList);

		for(u32 i = 0 ; i < pInterface->Roster.GetNumItem() ; i++)
		{
			string available;
			if(pInterface->Roster.GetItem(i).IsAvailable())
			available = " available ";
			else
			available = "unavailable";
			
			mvwprintw(pInterface->pWinHostList, i + 2, 1, "[%d][%s] %s\n", i,
						available.c_str(),
						pInterface->Roster.GetItem(i).GetJid().GetFull().c_str());
		}
		
		wrefresh(pInterface->pMainWin);
		wrefresh(pInterface->pWinHostList);
		pInterface->MutexOnDisplay.UnLock();
	}
	while(pInterface->pResox->OnRosterUpdated(&pInterface->Roster));

	
	return NULL;
}

CInterfaceException::CInterfaceException(int code) : CException(code)
{}

CInterfaceException::~CInterfaceException() throw()
{}

const char* CInterfaceException::what() const throw()
{
	switch(GetCode())
	{
	case IEC_CONSTRUCTORERROR:
		return "CInterface::Constructor() error";

	default:
		return "CInterface: unknown error";
	}
	
}
