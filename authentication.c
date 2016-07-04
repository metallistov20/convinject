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

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <libssh/libssh.h>

#include "examples_common.h"

int authenticate_kbdint(ssh_session session, const char *password)
{
int err;

	err = ssh_userauth_kbdint(session, NULL, NULL);

	while (err == SSH_AUTH_INFO)
	{
	const char *instruction;
	const char *name;
	char buffer[128];
	int i, n;

		name = ssh_userauth_kbdint_getname(session);

		instruction = ssh_userauth_kbdint_getinstruction(session);

		n = ssh_userauth_kbdint_getnprompts(session);

		if (name && strlen(name) > 0)
		{
			printf("%s\n", name);
		}

		if (instruction && strlen(instruction) > 0)
		{
			printf("%s\n", instruction);
		}

		for (i = 0; i < n; i++)
		{
		const char *answer;
		const char *prompt;
		char echo;

			prompt = ssh_userauth_kbdint_getprompt(session, i, &echo);

			if (prompt == NULL)
			{
				break;
			}

			if (echo)
			{
			char *p;

				printf("%s", prompt);

				if (fgets(buffer, sizeof(buffer), stdin) == NULL)
				{
					return SSH_AUTH_ERROR;
				}

				buffer[sizeof(buffer) - 1] = '\0';

				if ((p = strchr(buffer, '\n')))
				{
					*p = '\0';
				}

				if (ssh_userauth_kbdint_setanswer(session, i, buffer) < 0)
				{
					return SSH_AUTH_ERROR;
				}

				memset(buffer, 0, strlen(buffer));

			}
			else
			{
				if (password && strstr(prompt, "Password:"))
				{
					answer = password;
				}
				else
				{
					buffer[0] = '\0';

					if (ssh_getpass(prompt, buffer, sizeof(buffer), 0, 0) < 0)
					{
						return SSH_AUTH_ERROR;
					}
					answer = buffer;
				}

				err = ssh_userauth_kbdint_setanswer(session, i, answer);

				memset(buffer, 0, sizeof(buffer));

				if (err < 0)
				{
					return SSH_AUTH_ERROR;
				}
			}

		} /* for (i = 0; i < n; i++) */

		err=ssh_userauth_kbdint(session,NULL,NULL);

	} /* 	while (err == SSH_AUTH_INFO) */

	return err;
}

static void error(ssh_session session)
{
	fprintf(stderr,"Authentication failed: %s\n",ssh_get_error(session));
}

#define PASSWORD_INSTANCE "admin"

int authenticate_console(ssh_session session)
{
int rc;
int method;
char password[128] = {0};
char *banner;

	/* Try to authenticate */
	rc = ssh_userauth_none(session, NULL);

	if (rc == SSH_AUTH_ERROR)
	{
		error(session);

		return rc;
	}

	method = ssh_userauth_list(session, NULL);

	while (rc != SSH_AUTH_SUCCESS)
	{
		if (method & SSH_AUTH_METHOD_GSSAPI_MIC)
		{
			rc = ssh_userauth_gssapi(session);

			if(rc == SSH_AUTH_ERROR)
			{
				error(session);
				return rc;
			}
			else if (rc == SSH_AUTH_SUCCESS)
			{
				break;
			}
		}

		/* Try to authenticate with public key first */
		if (method & SSH_AUTH_METHOD_PUBLICKEY)
		{
			rc = ssh_userauth_publickey_auto(session, NULL, NULL);

			if (rc == SSH_AUTH_ERROR)
			{
				error(session);
				return rc;
			}
			else if (rc == SSH_AUTH_SUCCESS)
			{
				break;
			}
		}

		/*Try to authenticate with keyboard interactive" */
		if (method & SSH_AUTH_METHOD_INTERACTIVE)
		{
			rc = authenticate_kbdint(session, NULL);

			if (rc == SSH_AUTH_ERROR)
			{
				error(session);
				return rc;
			}
			else if (rc == SSH_AUTH_SUCCESS)
			{
				break;
			}
		}

#if (0)
		if (ssh_getpass("Password: ", password, sizeof(password), 0, 0) < 0)
		{
			return SSH_AUTH_ERROR;
		}
#else

		/* Notmally we shoud interact with SSH/CLI as less as we wish */
		memcpy(password, PASSWORD_INSTANCE, strlen(PASSWORD_INSTANCE) + 1 );

#endif
		/* Try to authenticate with password */
		if (method & SSH_AUTH_METHOD_PASSWORD)
		{
			rc = ssh_userauth_password(session, NULL, password);

			if (rc == SSH_AUTH_ERROR)
			{
				error(session);

				return rc;
			}
			else
				if (rc == SSH_AUTH_SUCCESS)
				{
					break;
				}
		}

		memset(password, 0, sizeof(password));
	}

	banner = ssh_get_issue_banner(session);

	if (banner)
	{
		printf("%s\n",banner);

		ssh_string_free_char(banner);
	}

	return rc;
}
