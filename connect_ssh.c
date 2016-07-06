/*
 (C) Copyright 2016, TP-Link Inc, konstantin.mauch@tp-link.com

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; either version 2 of
 the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT any WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 MA 02111-1307 USA
*/

#include <libssh/libssh.h>

#include "examples_common.h"

#include <stdio.h>

ssh_session connect_ssh(const char *host, const char *user,int verbosity)
{
ssh_session session;

int auth=0;

	session=ssh_new();

	if (NULL == session)
	{
		return NULL;
	}

	if(NULL != user)
	{
		if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0)
		{
			ssh_free(session);

			return NULL;
		}
	}

	if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0)
	{
		ssh_free(session);

		return NULL;
	}

	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

	if(ssh_connect(session))
	{
		fprintf(stderr,"Connection failed : %s\n",ssh_get_error(session));

		ssh_disconnect(session);

		ssh_free(session);

		return NULL;
	}

	if(verify_knownhost(session)<0)
	{
		ssh_disconnect(session);

		ssh_free(session);

		return NULL;
	}

	auth=authenticate_console(session);

	if(SSH_AUTH_SUCCESS == auth)
	{
		return session;
	}
	else
		if(SSH_AUTH_DENIED == auth)
		{
			fprintf(stderr,"Authentication failed\n");
		}
		else
		{
			fprintf(stderr,"Error while authenticating : %s\n",ssh_get_error(session));
		}

		ssh_disconnect(session);

		ssh_free(session);

		return NULL;
}
