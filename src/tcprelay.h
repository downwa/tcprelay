// tcprelay.h

// Copyright Sébastien Millet, 2012, 2013, 2014

#ifdef HAVE_CONFIG_H
#include "../config.h"
#else
#include "../extracfg.h"
#endif

#include <sys/types.h>

#define UNUSED(x) (void)(x)

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#if defined(_WIN32) || defined(_WIN64)
typedef int socklen_t;
#define SHUT_RD		SD_RECEIVE 
#define SHUT_WR		SD_SEND 
#define SHUT_RDWR SD_BOTH 
#define EADDRINUSE	98
#endif

#define FALSE 0
#define TRUE	1

#define DEFAULT_CONNECT_TIMEOUT 5

#define REGULAR_STR_STRBUFSIZE 2000
#define ERR_STR_BUFSIZE 200
#define DEFAULT_BUFFER_SIZE 65536

#define SRVNAME_SIZE	500
#define PATHNAME_SIZE	1000

#define BIND_ERROR -1
#define LISTEN_ERROR -1
#define ACCEPT_ERROR -1
#define CONNECT_ERROR -1
#define SELECT_ERROR -1
#define RECV_ERROR -1
#define SEND_ERROR -1
#define SETSOCKOPT_ERROR -1
#define GETTIMEOFDAY_ERROR -1

#define MAXSESSIONS 100
#define LOGROTATE_SECONDS	3600

	// Level of log
typedef enum {LL_ERROR = -1, LL_WARNING = 0, LL_NORMAL = 1, LL_VERBOSE = 2, LL_DEBUG = 3} loglevel_t;
	// Type of prefix output in the log
typedef enum {LP_DATETIME, LP_NOTHING, LP_2SPACE, LP_INDENT} logdisp_t;

struct telnet_t {
	char *base;
	char *write;
	int nb_chars;
	int last_cr;
	int telnet_ok;
};

void os_set_sock_nonblocking_mode(int sock);
void os_set_sock_blocking_mode(int sock);
int os_last_err();
char *os_last_err_desc(char *s, size_t s_bufsize);
void os_init_network();
int os_last_network_op_is_in_progress();
void os_closesocket(int sock);

void fatal_error(const char *format, ...);

void bindPort(int session_nr);

void my_logf(const loglevel_t log_level, const logdisp_t log_disp, const char *format, ...);
