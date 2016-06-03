#include "config.h"

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <sys/select.h>

#include <sys/time.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif


#include <sys/ioctl.h>

#include <signal.h>

#include <errno.h>

#include <fcntl.h>

#include <libssh/callbacks.h>

#include <libssh/libssh.h>

#include <libssh/sftp.h>

#include "examples_common.h"

#define MAXCMD 10

static char *host;
static char *user;
static char *cmds[MAXCMD];
static struct termios terminal;

static char *pcap_file=NULL;

static char *proxycommand;

static int auth_callback(const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata)
{
(void) verify;
(void) userdata;

	return ssh_getpass(prompt, buf, len, echo, verify);
}

struct ssh_callbacks_struct cb = {
		.auth_function=auth_callback,
		.userdata=NULL
};

static void add_cmd(char *cmd)
{
int n;

	for (n = 0; (n < MAXCMD) && cmds[n] != NULL; n++);

	if (n == MAXCMD)
	{
		return;
	}

	cmds[n]=strdup(cmd);
}

static void usage()
{
	fprintf(stderr,"Usage : ssh [options] [login@]hostname\n"
	"sample client - libssh-%s\n"
	"Options :\n"
	"  -l user : log in as user\n"
	"  -p port : connect to port\n"
	"  -d : use DSS to verify host public key\n"
	"  -r : use RSA to verify host public key\n"
#ifdef WITH_PCAP
	"  -P file : create a pcap debugging file\n"
#endif
    		,
	ssh_version(0));

	exit(0);
}

static int opts(int argc, char **argv)
{
int i;

	while( -1 != (i=getopt(argc,argv,"T:P:"))  )
	{
		switch(i)
		{
			case 'P':
				pcap_file=optarg;
				break;

			default:
				fprintf(stderr,"unknown option %c\n",optopt);
				usage();
		}
	}

	if(optind < argc)

		host=argv[optind++];

	while(optind < argc)

		add_cmd(argv[optind++]);

	if(NULL == host)

		usage();

	return 0;
}

#ifndef HAVE_CFMAKERAW
static void cfmakeraw(struct termios *termios_p)
{
	termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);

	termios_p->c_oflag &= ~OPOST;

	termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);

	termios_p->c_cflag &= ~(CSIZE|PARENB);

	termios_p->c_cflag |= CS8;
}
#endif


static void do_cleanup(int i)
{
/* unused variable */
(void) i;

	tcsetattr(0,TCSANOW,&terminal);
}

static void do_exit(int i)
{
/* unused variable */
(void) i;

	do_cleanup(0);

	exit(0);
}

ssh_channel chan;

int signal_delayed=0;

static void sigwindowchanged(int i)
{
	(void) i;

	signal_delayed=1;
}

static void setsignal(void)
{
	signal(SIGWINCH, sigwindowchanged);

	signal_delayed=0;
}

static void sizechanged(void)
{
struct winsize win = { 0, 0, 0, 0 };

	ioctl(1, TIOCGWINSZ, &win);

	ssh_channel_change_pty_size(chan,win.ws_col, win.ws_row);

	setsignal();
}

static void select_loop(ssh_session session,ssh_channel channel)
{
ssh_connector connector_in, connector_out, connector_err;
ssh_event event = ssh_event_new();
int iIdxDbg;

//printf("[%s][%s][%d]: doing STDIN \n", __FILE__, __func__, iIdxDbg++);
	/* stdin */
	connector_in = ssh_connector_new(session);
	ssh_connector_set_out_channel(connector_in, channel, SSH_CONNECTOR_STDOUT);
	ssh_connector_set_in_fd(connector_in, 0);
	ssh_event_add_connector(event, connector_in);

//printf("[%s][%s][%d]: doing STDOUT \n", __FILE__, __func__, iIdxDbg++);
	/* stdout */
	connector_out = ssh_connector_new(session);
	ssh_connector_set_out_fd(connector_out, 1);
	ssh_connector_set_in_channel(connector_out, channel, SSH_CONNECTOR_STDOUT);
	ssh_event_add_connector(event, connector_out);

    /* stderr */
//printf("[%s][%s][%d]: doing STDERR \n", __FILE__, __func__, iIdxDbg++);
	connector_err = ssh_connector_new(session);
	ssh_connector_set_out_fd(connector_err, 2);
	ssh_connector_set_in_channel(connector_err, channel, SSH_CONNECTOR_STDERR);
	ssh_event_add_connector(event, connector_err);

	while(ssh_channel_is_open(channel))
	{
//printf("[%s][%s][%d]: cycle; polling \n", __FILE__, __func__, iIdxDbg++);
		if(signal_delayed)
		{
//printf("[%s][%s][%d]: cycle; polling; sizechanged \n", __FILE__, __func__, iIdxDbg++);
		sizechanged();
		}

		ssh_event_dopoll(event, 60000);
    	}

//printf("[%s][%s][%d]: removing IN \n", __FILE__, __func__, iIdxDbg++);
	ssh_event_remove_connector(event, connector_in);
	ssh_event_remove_connector(event, connector_out);
	ssh_event_remove_connector(event, connector_err);
//printf("[%s][%s][%d]: removed ERR \n", __FILE__, __func__, iIdxDbg++);

	ssh_connector_free(connector_in);
	ssh_connector_free(connector_out);
	ssh_connector_free(connector_err);

	ssh_event_free(event);
	ssh_channel_free(channel);

printf("[%s][%s][%d]: finished \n", __FILE__, __func__, iIdxDbg++);

}

static void shell(ssh_session session)
{
ssh_channel channel;
struct termios terminal_local;
int interactive=isatty(0);
int iIdxDbg; 

	channel = ssh_channel_new(session);

	if(interactive)
	{
		tcgetattr(0,&terminal_local);

		memcpy(&terminal,&terminal_local,sizeof(struct termios));
	}
//printf("[%s][%s][%d]: ssh_channel_open_session \n", __FILE__, __func__, iIdxDbg++);

	if(ssh_channel_open_session(channel))
	{
		printf("error opening channel : %s\n",ssh_get_error(session));

		return;
	}

	chan=channel;

//printf("[%s][%s][%d]: ssh_channel_request_pty,  interactive=<%d>, channel=<%p>\n", __FILE__, __func__, iIdxDbg++, interactive, channel);

	if(interactive)
	{
		ssh_channel_request_pty(channel);

		sizechanged();
	}
//printf("[%s][%s][%d]: ssh_channel_request_shell, channel=<%p>\n", __FILE__, __func__, iIdxDbg++, channel);

	if(ssh_channel_request_shell(channel))
	{
		printf("Requesting shell : %s\n",ssh_get_error(session));

		return;
	}

//printf("[%s][%s][%d]: cfmakeraw-tcsetattr-setsignal, interactive=<%d>\n", __FILE__, __func__, iIdxDbg++, interactive);

	if(interactive)
	{
		cfmakeraw(&terminal_local);

		tcsetattr(0,TCSANOW,&terminal_local);

		setsignal();
	}

//printf("[%s][%s][%d]: signal-select_loop, interactive=<%d>\n", __FILE__, __func__, iIdxDbg++, interactive);

	signal(SIGTERM,do_cleanup);

	select_loop(session,channel);

//printf("[%s][%s][%d]: AFTER select_loop, interactive=<%d>\n", __FILE__, __func__, iIdxDbg++, interactive);

	if(interactive)

		do_cleanup(0);
}

static void batch_shell(ssh_session session)
{
ssh_channel channel;
char buffer[1024];
int i,s=0;

	for(i=0;i<MAXCMD && cmds[i];++i)
	{
		s+=snprintf(buffer+s,sizeof(buffer)-s,"%s ",cmds[i]);

		free(cmds[i]);

		cmds[i] = NULL;
	}

	channel=ssh_channel_new(session);

	ssh_channel_open_session(channel);

	if(ssh_channel_request_exec(channel,buffer))
	{
		printf("error executing \"%s\" : %s\n",buffer,ssh_get_error(session));

		return;
	}

	select_loop(session,channel);
}

static int client(ssh_session session)
{
int auth=0;
char *banner;
int state;

	if (user)
		if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0)
			return -1;

	if (ssh_options_set(session, SSH_OPTIONS_HOST ,host) < 0)
		return -1;

	if (proxycommand != NULL)
	{
		if(ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, proxycommand))

		return -1;
	}
	ssh_options_parse_config(session, NULL);

	if(ssh_connect(session))
	{
		fprintf(stderr,"Connection failed : %s\n",ssh_get_error(session));

		return -1;
	}

	state=verify_knownhost(session);

	if (state != 0)
		return -1;

	ssh_userauth_none(session, NULL);

	banner=ssh_get_issue_banner(session);

	if(banner)
	{
		printf("%s\n",banner);

		free(banner);
	}

	auth=authenticate_console(session);

	if(auth != SSH_AUTH_SUCCESS)
	{
		return -1;
	}

	if(!cmds[0])
		shell(session);
	else
		batch_shell(session);

	return 0;
}

ssh_pcap_file pcap;
void set_pcap(ssh_session session);

void set_pcap(ssh_session session)
{
	if(!pcap_file)

		return;

	pcap=ssh_pcap_file_new();

	if(!pcap)

		return;

	if(ssh_pcap_file_open(pcap,pcap_file) == SSH_ERROR)
	{
		printf("Error opening pcap file\n");

		ssh_pcap_file_free(pcap);

		pcap=NULL;

		return;
	}
	ssh_set_pcap_file(session,pcap);
}

void cleanup_pcap(void);

void cleanup_pcap()
{
	if(pcap)
		ssh_pcap_file_free(pcap);

	pcap=NULL;
}

int main(int argc, char **argv)
{
ssh_session session;

	session = ssh_new();

	ssh_callbacks_init(&cb);

	ssh_set_callbacks(session,&cb);

	if(ssh_options_getopt(session, &argc, argv))
	{
		fprintf(stderr, "error parsing command line :%s\n",

		ssh_get_error(session));

		usage();
	}

	opts(argc,argv);

	signal(SIGTERM, do_exit);

	set_pcap(session);

	client(session);

	ssh_disconnect(session);

	ssh_free(session);

	cleanup_pcap();

	ssh_finalize();

	return 0;
}
