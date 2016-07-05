#ifndef EXAMPLES_COMMON_H_
#define EXAMPLES_COMMON_H_

#include <libssh/libssh.h>
int authenticate_console(ssh_session session);

int authenticate_kbdint(ssh_session session, const char *password);

int verify_knownhost(ssh_session session);

ssh_session connect_ssh(const char *hostname, const char *user, int verbosity);

#endif /* EXAMPLES_COMMON_H_ */
