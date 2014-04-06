// tcprelay.c

// Copyright Sébastien Millet, 2012, 2013, 2014
// Portions of multiple-client support Copyright Warren Downs, 2014

#include "tcprelay.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>

#if defined(_WIN32) || defined(_WIN64)

	// WINDOWS
#include <winsock2.h>

#else

	// NOT WINDOWS
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include <signal.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>

loglevel_t opt_current_log_level = LL_NORMAL;

const char *DEFAULT_LOGFILE = PACKAGE_TARNAME ".log";
const char *SRV_SHORTNAME = "[SRV]";
const char *CLI_SHORTNAME = "[CLI]";
const char *PREFIX_RECEIVED = "<<< ";
const char *PREFIX_SENT = ">>> ";
#define DEFAULT_ROTATE_LOG_SIZE_KB 10240       // 10 MB of log by default, when rotation activated
#define MIN_ROTATE_LOG_SIZE_KB     20
#define MAX_ROTATE_LOG_SIZE_KB     2147483647  // Max 2 TB of log size
#define DEFAULT_ROTATE_LOG_NB_FILES   7
#define MAX_ROTATE_LOG_NB_FILES       49

/*#define DEBUG_META_LOG*/
#ifdef DEBUG_META_LOG
#define META_LOG_FILE "meta.log"
#endif

char opt_server_name[SRVNAME_SIZE];
char opt_logfile[PATHNAME_SIZE];
char opt_connexe[PATHNAME_SIZE]={0}; // Optional command to run at every connection

int opt_server_port = 0;
int opt_listen_port = 0;
ssize_t opt_bufsize = DEFAULT_BUFFER_SIZE;
int opt_connect_timeout = DEFAULT_CONNECT_TIMEOUT;
int opt_telnet_log = FALSE;
int opt_display_log = TRUE;
int opt_run_once = FALSE;
int opt_mirror_mode = FALSE;
int opt_test_mode = 0;
int opt_minimal_log = FALSE; // Turn off data logging
int opt_rotate_log = FALSE;
ssize_t opt_rotate_log_size_kb = DEFAULT_ROTATE_LOG_SIZE_KB;
int opt_rotate_log_nb_files = DEFAULT_ROTATE_LOG_NB_FILES;
	// Last byte of IP address used to form source port: Try up to 252 times
	// using this formula (where ipa is the last IP byte): p=1024+(256*n)+ipa
int opt_ip_as_port = FALSE;

FILE *g_log_fd = NULL;

int g_flag_interrupted = FALSE;
int g_quitting = FALSE;

int g_listen_sock;
int g_connection_socks[MAXSESSIONS];
int g_session_socks[MAXSESSIONS];
struct telnet_t g_telnet[MAXSESSIONS][2];
char* g_buffer[MAXSESSIONS];
int g_buffer_telnet_ok[MAXSESSIONS];
int g_connection_cli_is_live[MAXSESSIONS],connection_srv_is_live[MAXSESSIONS];
size_t g_telnet_str_bufsize;
int g_bport[MAXSESSIONS];

#include "bsdstring.c"
/* NOTE: Rationale for using BSD strlcat/strlcpy instead of strncat/strncpy:
 *       char *strncpy(char *dest, const char *src, size_t n);
 * strncat will use at most n bytes from source, but that may still overflow dest (if it has anything in it)
 * This common error happens because strncat's limit is not on the destination, but on the source
 * To avoid this, you would have to do something like the following:
 * int olen=max(0,REGULAR_STR_STRBUFSIZE-strlen(s)-1); if(olen>0) { strncat(dt, s, olen); }
 * Instead, we include strlcat for safer coding overall.
 * Nonetheless, we must still always null-terminate (truncate) our destination buffer if source is not
 * guaranteed to be null-terminated, since it is not guaranteed by any of the str*cpy/cat functions.
*/

/********************************************************************************/
/* OS SOCKETS                                                                   */
/********************************************************************************/

#if defined(_WIN32) || defined(_WIN64)

	// WINDOWS

void os_set_sock_nonblocking_mode(int sock) {
	u_long iMode = 1;
	int iResult = ioctlsocket(sock, FIONBIO, &iMode);
	if (iResult != NO_ERROR)
		fatal_error("ioctlsocket failed with error: %ld", iResult);
}

void os_set_sock_blocking_mode(int sock) {
	u_long iMode = 0;
	int iResult = ioctlsocket(sock, FIONBIO, &iMode);
	if (iResult != NO_ERROR)
		fatal_error("ioctlsocket failed with error: %ld", iResult);
}

int os_last_err() {
	int r = WSAGetLastError();
	//WSACleanup();
	return r;
}

char *os_last_err_desc(char *s, size_t s_bufsize) {
	LPVOID lpMsgBuf;
	DWORD last_err = WSAGetLastError();
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, last_err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
	char tmp[ERR_STR_BUFSIZE];
	strlcpy(tmp, (char *)lpMsgBuf, sizeof(tmp)); // NOTE: BSD strlcpy safer than strncpy
	tmp[ERR_STR_BUFSIZE-1]=0;                    // NOTE: Should always null-terminate (truncate) (not guaranteed otherwise)
	int n = strlen(tmp);
	if (n >= 2) {
		if (tmp[n - 2] == '\r' && tmp[n - 1] == '\n')
			tmp[n - 2] = '\0';
	}
	snprintf(s, s_bufsize, "code=%lu (%s)", last_err, tmp);
	//WSACleanup();
	return s;
}

void os_init_network() {
	WSADATA wsaData;
	int e;
	char s_err[ERR_STR_BUFSIZE];
	if ((e = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0) {
		fatal_error("WSAStartup() returned value %i, error: %s", e, os_last_err_desc(s_err, sizeof(s_err)));
		WSACleanup();
	}
}

int os_last_network_op_is_in_progress() {
	return (WSAGetLastError() == WSAEINPROGRESS || WSAGetLastError() == WSAEWOULDBLOCK);
}

void os_closesocket(int sock) {
	if(sock > -1) closesocket(sock); // NOTE: Added safety check
}

int os_e_exists(const char *path, const unsigned int my_flag, const int reverse) {
	DWORD dwAttrs = GetFileAttributes(path);
	if (dwAttrs == (DWORD)(INVALID_FILE_ATTRIBUTES))
		return FALSE;
	return ((dwAttrs & my_flag) != my_flag ? reverse : !reverse);
}
int os_file_exists(const char *path) { return os_e_exists(path, FILE_ATTRIBUTE_DIRECTORY, TRUE); }

int os_rename(const char *actual_name, const char* new_name) {
	if (os_file_exists(new_name))
		remove(new_name);
	return rename(actual_name, new_name);
}

#else

	// NOT WINDOWS

void os_set_sock_nonblocking_mode(int sock) {
	long arg = fcntl(sock, F_GETFL, NULL);
	arg |= O_NONBLOCK;
	fcntl(sock, F_SETFL, arg);
}

void os_set_sock_blocking_mode(int sock) {
	long arg = fcntl(sock, F_GETFL, NULL);
	arg &= ~O_NONBLOCK;
	fcntl(sock, F_SETFL, arg);
}

int os_last_err() {
	return errno;
}

char *os_last_err_desc(char *s, size_t s_bufsize) {
	snprintf(s, s_bufsize, "code=%i (%s)", errno, strerror(errno));
	return s;
}

void os_init_network() {
}

int os_last_network_op_is_in_progress() {
	return (errno == EINPROGRESS);
}

void os_closesocket(int sock) {
	if(sock > -1) close(sock); // NOTE: Added safety check
}

int os_e_exists(const char *path, const unsigned int my_flag) {
	struct stat st;

	if (stat(path, &st) != 0)
		return FALSE;
	return ((st.st_mode & S_IFMT) == my_flag);
}
int os_file_exists(const char *sz) { return os_e_exists(sz, S_IFREG); }

int os_rename(const char *actual_name, const char* new_name) {
	return rename(actual_name, new_name);
}

#endif


/********************************************************************************/
/* LOGGING                                                                      */
/********************************************************************************/
//
// Print an error in standard error and exit program
// if exit_program is true.
//
void fatal_error(const char *format, ...) {
	va_list args;
	va_start(args, format);

	char str[REGULAR_STR_STRBUFSIZE];
	vsnprintf(str, sizeof(str), format, args);
	strlcat(str, "\n", sizeof(str)); // NOTE: BSD strlcat is safer than strncat
	fprintf(stderr, str, NULL);
	my_logf(LL_ERROR, LP_DATETIME, "%s",str); // Log any fatal error
	va_end(args);
	exit(EXIT_FAILURE);
}

//
// Stops after an internal error
//
void internal_error(const char *desc, const char *source_file, const unsigned long int line) {
	fatal_error("Internal error %s, file %s, line %lu", desc, source_file, line);
}

//
// Initializes the program log
//
void my_log_open() {
	if (g_log_fd == NULL)
		g_log_fd = fopen(opt_logfile, "a");
}

//
// Closes the program log
//
void my_log_close() {
	if (g_log_fd) {
		fclose(g_log_fd);
		g_log_fd = NULL;
	}
}

//
// Prepare prefix string, used by my_log only
//
void my_log_core_get_dt_str(const logdisp_t log_disp, char *dt, size_t dt_bufsize) {
	time_t ltime = time(NULL);
	struct tm ts;
	ts = *localtime(&ltime);

	struct timeval tv;
	struct timezone tz;
	if (gettimeofday(&tv, &tz) == GETTIMEOFDAY_ERROR) {
		char s_err[ERR_STR_BUFSIZE];
		fatal_error("gettimeofday() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
	}

	snprintf(dt, dt_bufsize, "%02i/%02i/%02i %02i:%02i:%02i.%06lu  ", ts.tm_mday, ts.tm_mon + 1, ts.tm_year % 100,
		ts.tm_hour, ts.tm_min, ts.tm_sec, tv.tv_usec);
	if (log_disp == LP_NOTHING) {
		strlcpy(dt, "", dt_bufsize); // NOTE: BSD strlcpy is safer than strncpy
	} else if (log_disp == LP_2SPACE) {
		strlcpy(dt, "  ", dt_bufsize); // NOTE: BSD strlcpy is safer than strncpy
	} else if (log_disp == LP_INDENT) {
			memset(dt, ' ', strlen(dt));
	}
}

char *get_nth_logname(char *logname, const size_t len, const char *prefix, int i, const char *postfix) {
	if (i >= 1)
		snprintf(logname, len, "%s.%d%s", prefix, i, postfix);
	else
		snprintf(logname, len, "%s%s", prefix, postfix);
	return logname;
}

//
// Output log string, used by my_log only
//
void my_log_core_output(const char *s) {
	if (opt_rotate_log) {
		float lim_kb = ((float)opt_rotate_log_size_kb - .2) / ((float)opt_rotate_log_nb_files + 1);
		long pos;
		float ls_kb = -1;
		if (g_log_fd != NULL) {
			pos = ftell(g_log_fd);
			ls_kb = (float)pos / 1024;
		}

#ifdef DEBUG_META_LOG
			FILE *meta = fopen(META_LOG_FILE, "a");
			fprintf(meta, "log size=%f; pos=%lu; limit=%f\n", ls_kb, pos, lim_kb);
			fclose(meta);
#endif

		if (ls_kb > lim_kb) {

#ifdef DEBUG_META_LOG
			char dt[REGULAR_STR_STRBUFSIZE];
			my_log_core_get_dt_str(LP_DATETIME, dt, sizeof(dt));
			FILE *meta = fopen(META_LOG_FILE, "a");
			fprintf(meta, "\n%s  LOGROTEV -- Log rotation event\n", dt);
#endif

			my_log_close();
//
// WARNING
// FROM NOW ON THE LOG IS CLOSED => DON'T USE my_lofg or my_logs
//

			char logname[PATHNAME_SIZE];
			char prefix[PATHNAME_SIZE];
			char postfix[PATHNAME_SIZE];
			strlcpy(prefix, opt_logfile, sizeof(prefix));
			char *dot = strrchr(prefix, '.');
			if (dot != NULL) {
				strlcpy(postfix, dot, sizeof(postfix));
				*dot = '\0';
			} else {
				strlcpy(postfix, "", sizeof(postfix));
			}
			int last_seq;
			for (last_seq = 1; last_seq < opt_rotate_log_nb_files; ++last_seq) {
				get_nth_logname(logname, sizeof(logname), prefix, last_seq, postfix);
				int b = os_file_exists(logname);

#ifdef DEBUG_META_LOG
				fprintf(meta, "  File %s exists? -> %s\n", logname, b ? "yes" : "no");
#endif

				if (!b)
					break;
			}
			int i;
			char logname2[PATHNAME_SIZE];
			for (i = last_seq - 1; i >= 0; --i) {
				get_nth_logname(logname, sizeof(logname), prefix, i, postfix);
				get_nth_logname(logname2, sizeof(logname2), prefix, i + 1, postfix);

#ifdef DEBUG_META_LOG
				fprintf(meta, "  Renamnig %s into %s\n", logname, logname2);
#endif

				int e;
				if ((e = os_rename(logname, logname2))) {

#ifdef DEBUG_META_LOG
					char s_err[ERR_STR_BUFSIZE];
					fprintf(meta, "  rename error, value %d, error: %s\n", e, os_last_err_desc(s_err, sizeof(s_err)));
#endif

					break;
				} else {

#ifdef DEBUG_META_LOG
					fprintf(meta, "  Successfully renamed %s into %s\n", logname, logname2);
#endif

				}
			}

#ifdef DEBUG_META_LOG
			fclose(meta);
			meta = NULL;
#endif

			if (os_file_exists(opt_logfile)) {
					// Normally the code above has renamed files so the main log file should not
					// exist. If for whatever reason it failed, we do a last attempt to delete it,
					// as the priority is to keep log files total size below a certain value.
				remove(opt_logfile);
			}


		}
	}

	my_log_open();
//
// LOG IS OPEN AGAIN
// END OF WARNING
//

	fputs(s, g_log_fd);
	fputs("\n", g_log_fd);
	fflush(g_log_fd);
	if (opt_display_log) {
		puts(s);
		fflush(stdout);
	}
}

//
// Output a string in the program log
//
void my_logs(const loglevel_t log_level, const logdisp_t log_disp, const char *s) {
	if (log_level > opt_current_log_level)
		return;

	char dt[REGULAR_STR_STRBUFSIZE];

	my_log_core_get_dt_str(opt_test_mode >= 1 ? LP_NOTHING : log_disp, dt, sizeof(dt));
	strlcat(dt, s, sizeof(dt)); // NOTE: BSD strlcat is safer than strncat
	dt[REGULAR_STR_STRBUFSIZE-1]=0;         // NOTE: Should always null-terminate (truncate) (not guaranteed otherwise)
	my_log_core_output(dt);

}

//
// Output a formatted string in the program log
//
void my_logf(const loglevel_t log_level, const logdisp_t log_disp, const char *format, ...) {
	va_list args;
	va_start(args, format);

	if (log_level > opt_current_log_level)
		return;

	char dt[REGULAR_STR_STRBUFSIZE];
	char str[REGULAR_STR_STRBUFSIZE];

	my_log_core_get_dt_str(opt_test_mode >= 1 ? LP_NOTHING : log_disp, dt, sizeof(dt));

	vsnprintf(str, sizeof(str), format, args);
	strlcat(dt, str, sizeof(dt)); // NOTE: BSD strlcat is safer than strncat
	dt[REGULAR_STR_STRBUFSIZE-1]=0;           // NOTE: Should always null-terminate (truncate) (not guaranteed otherwise)
	my_log_core_output(dt);

	va_end(args);
}

//
// Log a telnet line
//
void my_log_telnet(const int is_received, const char *s, const char *pref) {
	if(opt_minimal_log) { return; }
	char prefix[50];
	snprintf(prefix, sizeof(prefix), "%s %s", pref, is_received ? PREFIX_RECEIVED : PREFIX_SENT);
	size_t m = strlen(prefix) + strlen(s) + 1;
	char tmp[m];
	strlcpy(tmp, prefix, m+1); // NOTE: BSD strlcpy safer than strncpy
	strlcat(tmp, s, m+1);      // NOTE: BSD strlcat safer than strncat
	my_logs(LL_NORMAL, LP_DATETIME, tmp);
}

//
// Convert a set of data in a printable string, made of hex digits and
// literal characters at the end.
// It produces lines like this one:
// "0000: 7f 45 4c 46 02 01 01 00   00 00 00 00 00 00 00 00  .ELF............"
//
const unsigned int hexline_strbufsize = 74;
void get_hex_line(const char *data, const unsigned int offset, const unsigned int nb_bytes, char *str,
		const unsigned int strbufsize, int *telnet_ok) {

	const int shift = 0;

	if (strbufsize < hexline_strbufsize) {
		internal_error("get_hex_line-01", __FILE__, __LINE__);
	}
	if (nb_bytes < 1 || nb_bytes > 16) {
		internal_error("get_hex_line-02", __FILE__, __LINE__);
	}
	memset(str, ' ', (size_t)(73 + shift));
	unsigned char c;
	char c_hexa[3];
	snprintf(str + shift, strbufsize, "%04x", offset);
	str[strlen(str)] = ':';
	int curs_hexa = 6 + shift;
	int curs_char = 57 + shift;
	unsigned char c_char;
	unsigned int i;
	for (i = 0; i < nb_bytes; i++) {
		c = (unsigned char)data[i + offset];
		snprintf(c_hexa, 3, "%02x", c);
		str[curs_hexa] = c_hexa[0];
		str[curs_hexa + 1] = c_hexa[1];
		if (i == 7) {
			curs_hexa += 5;
		} else {
			curs_hexa += 3;
		}
		if (c >= 32 && c <= 127) {
			c_char = c;
		} else {
			c_char = '.';
			if (!isspace(c) && (c < 32 || c > 127)) {
				*telnet_ok = FALSE;
			}
		}
		str[curs_char] = (char)c_char;
		curs_char++;
	}
	str[73 + shift] = '\0';
}

//
// Display the buffer in the log
//
void my_log_buffer(const char *buf, const unsigned int nb_bytes, int *telnet_ok) {
	if(opt_minimal_log) { return; }
	char s[hexline_strbufsize];
	unsigned int nb_on_line;

	unsigned int offset;
	for (offset = 0; offset < nb_bytes; offset += 16) {
		nb_on_line = nb_bytes - offset;
		if (nb_on_line > 16) {
			nb_on_line = 16;
		}
		get_hex_line(buf, offset, nb_on_line, s, hexline_strbufsize, telnet_ok);
		my_logs(LL_NORMAL, LP_2SPACE, s);
	}
}

/********************************************************************************/
/* SESSION UTILITIES                                                            */
/********************************************************************************/
int closeSession(int session_nr, int current_fd, const char *i_name) {
	int doBreak=FALSE;
	if (current_fd == g_connection_socks[session_nr]) {
		shutdown(g_connection_socks[session_nr],SHUT_RD); g_connection_cli_is_live[session_nr]=FALSE; doBreak=TRUE;
	}
	if (current_fd == g_session_socks[session_nr]) {
		shutdown(g_session_socks[session_nr],SHUT_RD); connection_srv_is_live[session_nr]=FALSE; doBreak=TRUE;
	}
	// NOTE: Close both sockets only when other end of both sockets has performed an orderly shutdown
	if(!g_connection_cli_is_live[session_nr] && !connection_srv_is_live[session_nr]) {
		if(g_connection_socks[session_nr] != -1) { os_closesocket(g_connection_socks[session_nr]); g_connection_socks[session_nr]=-1; }
		if(g_session_socks[session_nr] != -1) { os_closesocket(g_session_socks[session_nr]); g_session_socks[session_nr]=-1; }
		// Free allocated memory
		free(g_buffer[session_nr]); g_buffer[session_nr]=NULL;
		if (!opt_telnet_log && g_buffer_telnet_ok[session_nr] && !opt_minimal_log) {
			my_logf(LL_WARNING, LP_DATETIME, "%s: all characters exchanged were printable, consider using option --telnet", i_name);
		}
		int it;
		for (it = 0; it < 2; it++) { free(g_telnet[session_nr][it].base); g_telnet[session_nr][it].base=NULL; }
	}
	return doBreak;
}

// Find an available session (one that has both sockets closed)
int alloc_session() {
	int xa;
	for(xa=0; xa<MAXSESSIONS; xa++) {
		if(g_connection_socks[xa] == -1 && g_session_socks[xa] == -1) { return xa; }
	}
	return -1;
}

// FIXME
// Need to be passed as function argument and removed from global variables

	// String to print the description of the target server, like "servername:port"
char server_desc[200];
	// Resolving server name
struct sockaddr_in server;
struct hostent *hostinfo = NULL;

int connect_with_timeout(const struct sockaddr_in *srv, int *connection_sock, struct timeval *tv, const char *desc, int session_nr);

int newSession() {
	struct sockaddr_in client;
	socklen_t client_size = sizeof(client);
	int session_nr=alloc_session();
	if(session_nr == -1) {
		my_logf(LL_ERROR, LP_DATETIME, "alloc_session() out of available sessions (more than %d sessions in use)", MAXSESSIONS);
		return -1;
	}

		// String to store error descriptions
	char s_err[ERR_STR_BUFSIZE];

// 1. Accept an incoming connection

	my_logf(LL_DEBUG, LP_DATETIME, "Session %d accepting on port %i...", session_nr, opt_listen_port);
	if ((g_session_socks[session_nr] = accept(g_listen_sock, (struct sockaddr *) &client, &client_size)) == ACCEPT_ERROR) {
		if (g_flag_interrupted) { return -1; } // Cancel new session
		my_logf(LL_ERROR, LP_DATETIME, "accept() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
		return -1;
	}
	char ipaddr[16];
	strlcpy(ipaddr, inet_ntoa(client.sin_addr), sizeof(ipaddr)); // NOTE: BSD strlcpy safer than strncpy
	my_logf(LL_NORMAL, LP_DATETIME, "Accepted connection from %s: session_nr=%d", ipaddr, session_nr/*g_session_socks[session_nr]*/);
	if(opt_ip_as_port) {
		char *pp=strrchr(ipaddr,'.');
		g_bport[session_nr]=0;
		if(pp) { g_bport[session_nr]=atoi(&pp[1]); }
	}

// 2. Connect to remote server

	if (opt_mirror_mode) {
		g_connection_socks[session_nr] = -1;
	} else {
		if ((g_connection_socks[session_nr] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_ERROR) {
			fatal_error("socket() error to create connection socket, %s", os_last_err_desc(s_err, sizeof(s_err)));
		}
		server.sin_family = AF_INET;
		server.sin_port = htons((uint16_t)opt_server_port);
		server.sin_addr = *(struct in_addr *)hostinfo->h_addr;
		my_logf(LL_VERBOSE, LP_DATETIME, "Connecting to %s...", server_desc);
			// tv value is undefined after call to connect() as per documentation, so
			// it is to be re-set every time.
		struct timeval tv; // time value
		tv.tv_sec = opt_connect_timeout;
		tv.tv_usec = 0;
		if (connect_with_timeout(&server, &g_connection_socks[session_nr], &tv, server_desc, session_nr) != 0) {
			os_closesocket(g_session_socks[session_nr]); g_session_socks[session_nr]=-1;
			return -1;
		}
		my_logf(LL_NORMAL, LP_DATETIME, "Connected to %s: session_nr=%d", server_desc, session_nr/*_connection_socks[session_nr]*/);
	}
		// Prepare resources to manage relaying: buffer to exchange data through the network
		// (buffer), and strings to log trafic in telnet-style.
	g_buffer[session_nr] = (char *)malloc((size_t)opt_bufsize);
	g_buffer_telnet_ok[session_nr] = TRUE;
	int it;
	for (it = 0; it < 2; it++) {
		g_telnet[session_nr][it].base = (char *)malloc(g_telnet_str_bufsize);
		g_telnet[session_nr][it].write = g_telnet[session_nr][it].base;
		g_telnet[session_nr][it].nb_chars = 0;
		g_telnet[session_nr][it].last_cr = FALSE;
		g_telnet[session_nr][it].telnet_ok = TRUE;
	}

	if(opt_connexe[0]) {
#if defined(_WIN32) || defined(_WIN64)
		char cmd[MAX_PATH * 2];
		snprintf(cmd, sizeof(cmd), "\"%s\" \"%s\"", opt_connexe, ipaddr);

		STARTUPINFO si;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		PROCESS_INFORMATION cmd_pi;
		ZeroMemory(&cmd_pi, sizeof(cmd_pi));

		if(!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &cmd_pi)) {
			my_logf(LL_ERROR, LP_DATETIME, "CreateProcess error, %s", os_last_err_desc(s_err, sizeof(s_err)));
		}
#else
		pid_t child_pid;
		if((child_pid = fork()) < 0 ) {
			my_logf(LL_ERROR, LP_DATETIME, "fork() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
		}
		else if(child_pid == 0) { // Child
			// Close unused child fds to free resources
			// NOTE: This *could* be disabled if child needs to send over socket, but that would have to
			// be coordinated with server to avoid confusion.
			int xa;
			for(xa=0; xa<MAXSESSIONS; xa++) {
				if(g_connection_socks[xa] != -1) { close(g_connection_socks[xa]); }
				if(g_session_socks[xa] != -1)    { close(g_session_socks[xa]); }
			}
			// Now exec
			my_logf(LL_VERBOSE, LP_DATETIME, "Exec child %s %s", opt_connexe, ipaddr);
			execl(opt_connexe, opt_connexe, ipaddr, NULL);
			my_logf(LL_ERROR, LP_DATETIME, "execl() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
			_exit(1); // Exiting child, not the parent
		}
#endif
	}
	return session_nr;
}

/* bindPort purpose: Bind to a local port as a method of communicating to the receiver what the source ip
 * address is. The receiver (server) can use the source port MOD 256 minus 1024 to determine the last
 * byte of the 4 byte IP address (the other three bytes must be assumed to be on the same "class C" network)
 */
void bindPort(int session_nr) {

		// String to store error descriptions
	char s_err[ERR_STR_BUFSIZE];

	int sport=-1;
		// Optionally try to use last byte of client IP address as source port when connecting to server
		// Try up to 252 times using this formula (where ipa is the last IP byte): p=1024+(256*n)+ipa
		// This can be useful for server to know which client connected to it
	if(opt_ip_as_port) {
		int myport=g_bport[session_nr]+1024;

		for(sport=myport; sport<65535; sport+=256) {
			struct sockaddr_in sname;
			sname.sin_family = AF_INET;
			sname.sin_addr.s_addr = htonl(INADDR_ANY);
			sname.sin_port = htons((uint16_t)sport);
			if (bind(g_connection_socks[session_nr], (struct sockaddr *)&sname, sizeof(sname)) == SOCKET_ERROR) {
				if(errno == EADDRINUSE) {
					my_logf(LL_DEBUG, LP_DATETIME, "bind() trying again, %s", os_last_err_desc(s_err, sizeof(s_err)));
					continue;
				}
				my_logf(LL_ERROR, LP_DATETIME, "bind() error on connection socket, %s", os_last_err_desc(s_err, sizeof(s_err)));
			}
			break;
		}
		my_logf(LL_DEBUG, LP_DATETIME, "Source port is %d", sport);
	}
}

//
// Connect to a remote host, with a timeout
// Return 0 if success, a non-zero value if failure
//
int connect_with_timeout(const struct sockaddr_in *srv, int *connection_sock, struct timeval *tv, const char *desc, int session_nr) {
	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET((unsigned int)*connection_sock, &fdset);

		// String to store error descriptions
	char s_err[ERR_STR_BUFSIZE];

	os_set_sock_nonblocking_mode(*connection_sock);

	bindPort(session_nr);

	int res = 0;
	if (connect(*connection_sock, (struct sockaddr *)srv, sizeof(*srv)) == CONNECT_ERROR) {
		if (os_last_network_op_is_in_progress()) {
			if (select((*connection_sock) + 1, NULL, &fdset, NULL, tv) <= 0) {
				my_logf(LL_ERROR, LP_DATETIME, "Timeout connecting to %s, %s", desc, os_last_err_desc(s_err, sizeof(s_err)));
				res = 1;
			} else {
				int so_error;
				socklen_t len = sizeof(so_error);
				getsockopt(*connection_sock, SOL_SOCKET, SO_ERROR, (void*)&so_error, &len);
				if (so_error != 0) {
					my_logf(LL_ERROR, LP_DATETIME, "Socket error connecting to %s, code=%i (%s)", desc, so_error, strerror(so_error));
				}
				res = (so_error != 0);
			}
		} else {
			my_logf(LL_ERROR, LP_DATETIME, "Error connecting to %s, %s", desc, os_last_err_desc(s_err, sizeof(s_err)));
			res = 1;
		}
	} else {
		abort();
	}

	os_set_sock_blocking_mode(*connection_sock);

	return res;
}


/********************************************************************************/
/* MAIN LOOP                                                                    */
/********************************************************************************/

// NOTE: Added multiplexing of connections so several connections can be relayed simultaneously

//
// Main loop
//
void almost_neverending_loop() {
		// String to store error descriptions
	char s_err[ERR_STR_BUFSIZE];

	if (opt_mirror_mode) {
		my_logf(LL_VERBOSE, LP_DATETIME, "Mode: mirror");
		my_logf(LL_VERBOSE, LP_DATETIME, "Server: n/a");
		my_logf(LL_VERBOSE, LP_DATETIME, "Server port: n/a");
	} else {
		my_logf(LL_VERBOSE, LP_DATETIME, "Mode: connection to server");
		my_logf(LL_VERBOSE, LP_DATETIME, "Server: %s", opt_server_name);
		my_logf(LL_VERBOSE, LP_DATETIME, "Server port: %i", opt_server_port);
	}
	my_logf(LL_VERBOSE, LP_DATETIME, "Listening port: %u", opt_listen_port);
	my_logf(LL_VERBOSE, LP_DATETIME, "Log file: %s", opt_logfile);
	my_logf(LL_VERBOSE, LP_DATETIME, "Rotate log: %s", opt_rotate_log ? "yes" : "no");
	if (opt_rotate_log) {
		my_logf(LL_VERBOSE, LP_DATETIME, "Rotate log size (KB): %lu", opt_rotate_log_size_kb);
		my_logf(LL_VERBOSE, LP_DATETIME, "Rotate log nb files: %d", opt_rotate_log_nb_files);
	}
	my_logf(LL_VERBOSE, LP_DATETIME, "Display log: %s", opt_display_log ? "yes" : "no");
	my_logf(LL_VERBOSE, LP_DATETIME, "Telnet log: %s", opt_telnet_log ? "yes" : "no");
	my_logf(LL_VERBOSE, LP_DATETIME, "Minimal log: %s", opt_minimal_log ? "yes" : "no");
	my_logf(LL_VERBOSE, LP_DATETIME, "Ip as port: %s", opt_ip_as_port ? "yes" : "no");
	my_logf(LL_VERBOSE, LP_DATETIME, "Buffer size: %lu", opt_bufsize);
	my_logf(LL_VERBOSE, LP_DATETIME, "Connection timeout: %i", opt_connect_timeout);
	my_logf(LL_VERBOSE, LP_DATETIME, "Run once: %s", opt_run_once ? "yes" : "no");
	my_logf(LL_VERBOSE, LP_DATETIME, "Log level: %i", opt_current_log_level);
	my_logf(LL_VERBOSE, LP_DATETIME, "Test mode: %i", opt_test_mode);

	snprintf(server_desc, 200, "%s:%i", opt_server_name, opt_server_port);

		// Short string to print the name of the connecting point a packet was received from
	char i_name[50];

	if (!opt_mirror_mode) {
		my_logf(LL_DEBUG, LP_DATETIME, "Running gethosbyname() on %s", opt_server_name);
		hostinfo = gethostbyname(opt_server_name);
		if (hostinfo == NULL) {
			fatal_error("Unknown host %s, %s", opt_server_name, os_last_err_desc(s_err, sizeof(s_err)));
		}
	}

		// Putting in place listening socket
	if ((g_listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_ERROR) {
		fatal_error("socket() error to create listening socket, %s", os_last_err_desc(s_err, sizeof(s_err)));
	}
	int on = 1;
	if (setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) == SETSOCKOPT_ERROR) {
		fatal_error("setsockopt() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
	}

	struct sockaddr_in name;
	name.sin_family = AF_INET;
	name.sin_addr.s_addr = htonl(INADDR_ANY);
	name.sin_port = htons((uint16_t)opt_listen_port);
	if (bind(g_listen_sock, (struct sockaddr *)&name, sizeof(name)) == SOCKET_ERROR) {
		fatal_error("bind() error on listening socket, %s", os_last_err_desc(s_err, sizeof(s_err)));
	}
	if (listen(g_listen_sock, 1) == LISTEN_ERROR) {
		fatal_error("listen() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
	}

/*  int fdmax;*/
	int current_fd;

	fd_set fdset;

	int telnet_max_line_size_hit;

	char mystring[500];

	ssize_t nb_bytes_received;
	ssize_t nb_bytes_sent;
	int resend_sock;
/*  int warned_buffer_too_small;*/

	do {
		telnet_max_line_size_hit = FALSE;
/*    warned_buffer_too_small = FALSE;*/

			/** Add all sockets to fdset (including listen socket, to be notified of new connections) **/
		FD_ZERO(&fdset);
		FD_SET((unsigned int)g_listen_sock, &fdset);
		int fdmax=g_listen_sock;
		int xa;
		for(xa=0; xa<MAXSESSIONS; xa++) { // Add all active sockets
			if(g_connection_socks[xa] > -1) {
				FD_SET((unsigned int)g_connection_socks[xa], &fdset); my_logf(LL_DEBUG, LP_DATETIME, "Watching conn fd %d",g_connection_socks[xa]);
			}
			if(g_session_socks[xa] > -1) {
				FD_SET((unsigned int)g_session_socks[xa], &fdset); my_logf(LL_DEBUG, LP_DATETIME, "Watching sess fd %d",g_session_socks[xa]);
			}
			if(g_connection_socks[xa] > fdmax) { fdmax=g_connection_socks[xa]; }
			if(g_session_socks[xa] > fdmax) { fdmax=g_session_socks[xa]; }
		}
		my_logf(LL_DEBUG, LP_DATETIME, "select wait fdmax+1=%d",fdmax+1);
		int ret=select(fdmax + 1, &fdset, NULL, NULL, NULL);
		if (ret == SELECT_ERROR) {
			if(errno == EINTR && !g_flag_interrupted) { continue; }
			if (!g_flag_interrupted) {
				fatal_error("select() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
			}
			exit(EXIT_SUCCESS);
		}
		my_logf(LL_DEBUG, LP_DATETIME, "select:activity on %d fds...",ret);

		int session_nr=-1; // Which session is demanding attention

		// 3. Loop through both connections of all sessions to forward received data back and forth

		for (current_fd = 0; current_fd <= fdmax && !g_flag_interrupted; current_fd++) {
			if (!FD_ISSET(current_fd, &fdset)) { continue; }
			my_logf(LL_DEBUG, LP_DATETIME, "current_fd=%d",current_fd);
			if(current_fd == g_listen_sock) {
				session_nr=newSession();
				if(session_nr == -1 && g_flag_interrupted) { break; } // Cancel new session
				continue;
			}
			else { // Find session_nr for active fd
				session_nr=-1;
				for(xa=0; xa<MAXSESSIONS; xa++) { // Which session has this fd?
					if(g_connection_socks[xa] == current_fd || g_session_socks[xa] == current_fd) { session_nr=xa; break; }
				}
				if(session_nr == -1) {
					//fatal_error("Internal error never_ending_loop()-00, file %s, line %lu: activity on unexpected fd=%d (listen=%d)",  __FILE__, __LINE__,current_fd,g_listen_sock);
					continue; // FIXME: For now, simply ignore unexpected activity
				}
			}
			if (!opt_mirror_mode && current_fd == g_connection_socks[session_nr]) {
				snprintf(i_name,sizeof(i_name),"%s[%d]",SRV_SHORTNAME,session_nr);
			} else if (current_fd == g_session_socks[session_nr]) {
				snprintf(i_name,sizeof(i_name),"%s[%d]",CLI_SHORTNAME,session_nr);
			} else {
				fatal_error("Internal error never_ending_loop()-01, file %s, line %lu: activity on unexpected fd=%d (listen=%d)",  __FILE__, __LINE__,current_fd,g_listen_sock);
				//internal_error("never_ending_loop()-01: activity on unexpected fd=%d (listen=%d)", __FILE__, __LINE__,current_fd,g_listen_sock);
			}
			if ((nb_bytes_received = recv(current_fd, g_buffer[session_nr], (size_t)opt_bufsize, 0)) == RECV_ERROR) {
				my_logf(LL_ERROR, LP_DATETIME, "%s: recv() error, %s", i_name, os_last_err_desc(s_err, sizeof(s_err)));
				closeSession(session_nr, current_fd, i_name);
			} else if (nb_bytes_received == 0) {
				my_logf(LL_NORMAL, LP_DATETIME, "%s: closed connection", i_name);
				closeSession(session_nr, current_fd, i_name);
			} else {
			/* NOTE: It is not an error to receive less than the full amount available.  It could be that your CPU was too busy
			*       and your process blocked until a large amount of data was queued for delivery.
				if (nb_bytes_received == (ssize_t)bufsize && !warned_buffer_too_small) {
					my_logf(LL_WARNING, LP_DATETIME, "%s: recv() buffer size hit (size=%i)", i_name, bufsize);
					warned_buffer_too_small = TRUE;
				}
			*/
				if (opt_telnet_log) {
					int it = (current_fd == g_session_socks[session_nr] ? 0 : 1);
					char c;
					int bufwalker;
					for (bufwalker = 0; bufwalker < nb_bytes_received; bufwalker++) {
						c = g_buffer[session_nr][bufwalker];
						if (c == '\n' && g_telnet[session_nr][it].last_cr) {
							*(g_telnet[session_nr][it].write - 1) = '\0';
							my_log_telnet(!opt_mirror_mode && current_fd == g_connection_socks[session_nr], g_telnet[session_nr][it].base, i_name);
							g_telnet[session_nr][it].write = g_telnet[session_nr][it].base;
							g_telnet[session_nr][it].nb_chars = 0;
						} else {
							if ((size_t)g_telnet[session_nr][it].nb_chars >= g_telnet_str_bufsize - 1) {
								*(g_telnet[session_nr][it].write) = '\0';
								my_log_telnet(!opt_mirror_mode && current_fd == g_connection_socks[session_nr], g_telnet[session_nr][it].base, i_name);
								g_telnet[session_nr][it].write = g_telnet[session_nr][it].base;
								g_telnet[session_nr][it].nb_chars = 0;
								if (!telnet_max_line_size_hit) {
									my_logf(LL_WARNING, LP_DATETIME,
																"%s: telnet max line size hit, consider increasing it by increasing the buffer size", i_name);
									telnet_max_line_size_hit = TRUE;
								}
							}
							*(g_telnet[session_nr][it].write) = c;
							g_telnet[session_nr][it].write++;
							g_telnet[session_nr][it].nb_chars++;
						}
						g_telnet[session_nr][it].last_cr = (c == '\r');
						if (g_telnet[session_nr][it].telnet_ok && c < 32 && (c != '\r' && c != '\n' && !isspace(c))) {
							my_logs(LL_WARNING, LP_DATETIME, "Unprintable character encountered although --telnet option in use");
							g_telnet[session_nr][it].telnet_ok = FALSE;
						}
					}
				} else {
					snprintf(mystring, sizeof(mystring), "%s sent %li bytes (0x%04X)", i_name, (long int)nb_bytes_received, (unsigned int)nb_bytes_received);
					my_logs(LL_NORMAL, LP_DATETIME, mystring);
					my_log_buffer(g_buffer[session_nr], (unsigned int)nb_bytes_received, &g_buffer_telnet_ok[session_nr]);
				}
				if (opt_mirror_mode) {
					resend_sock = g_session_socks[session_nr];
				} else {
					resend_sock = (current_fd == g_session_socks[session_nr] ? g_connection_socks[session_nr] : g_session_socks[session_nr]);
				}

				//my_logf(LL_DEBUG, LP_DATETIME, "Will forward TCP data to alternate peer, size: %li", (unsigned int)nb_bytes_received);
				ssize_t ofs=0;
				ssize_t len=nb_bytes_received;
				do {
					my_logf(LL_DEBUG, LP_DATETIME, "Will forward TCP data to alternate peer %d, size: %li", resend_sock, (unsigned int)len);
					if ((nb_bytes_sent = send(resend_sock, &g_buffer[session_nr][ofs], (size_t)len, 0)) == SEND_ERROR) {
						my_logf(LL_ERROR, LP_DATETIME, "send() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
						closeSession(session_nr, current_fd, i_name); break;
					}
					ofs+=nb_bytes_sent; len-=nb_bytes_sent;
				} while(len > 0); // Until all received bytes have been sent
			}
		} // END for(current_fd)

// The code below was found to be wrong when telnet runs in "mode character",
// that is the default under Windows. Having incomplete lines in a received
// TCP frame is fine...
/*    int it;*/
/*    for (it = 0; it < 2; it++) {*/
/*      if (telnet[session_nr][it].nb_chars >= 1) {*/
/*        my_logf(LL_WARNING, LP_DATETIME,*/
/*          "%s: pending characters not terminated by internet new line", (it == 0 ? CLI_SHORTNAME : SRV_SHORTNAME));*/
/*        *(telnet[session_nr][it].write) = '\0';*/
/*        my_log_telnet(it == 1, telnet[session_nr][it].base);*/
/*      }*/
/*    }*/
	} while (!opt_run_once);

	os_closesocket(g_listen_sock); g_listen_sock=-1;
}

/************************************************************************************************************/
/************************************************************************************************************/
/************************************************************************************************************/

//
// Manage atexit()
//
void atexit_handler() {
	if (g_quitting)
		return;
	g_quitting = TRUE;

	int xa;
	for(xa=0; xa<MAXSESSIONS; xa++) {
		if(g_connection_socks[xa] != -1) { os_closesocket(g_connection_socks[xa]); g_connection_socks[xa]=-1; }
		if(g_session_socks[xa] != -1) { os_closesocket(g_session_socks[xa]); g_session_socks[xa]=-1; }
	}

	os_closesocket(g_listen_sock); g_listen_sock=-1;

	my_logs(LL_ERROR, LP_DATETIME, PACKAGE_NAME " stop"); // Always log the important event of stopping
	my_logs(LL_ERROR, LP_NOTHING, "");
	my_log_close();
}

//
// Manage signals
//
void sigterm_handler(int sig) {
UNUSED(sig);

	g_flag_interrupted = TRUE;
	my_logs(LL_ERROR, LP_DATETIME, "Received TERM signal, quitting..."); // Log any signal that causes exit
	exit(EXIT_FAILURE);
}

void sigabrt_handler(int sig) {
UNUSED(sig);

	g_flag_interrupted = TRUE;
	my_logs(LL_ERROR, LP_DATETIME, "Received ABORT signal, quitting..."); // Log any signal that causes exit
	exit(EXIT_FAILURE);
}

void sigint_handler(int sig) {
UNUSED(sig);

	g_flag_interrupted = TRUE;
	my_logs(LL_ERROR, LP_DATETIME, "Received INT signal, quitting..."); // Log any signal that causes exit
	exit(EXIT_FAILURE);
}

void sigsegv_handler(int sig) {
UNUSED(sig);

	g_flag_interrupted = TRUE;
	my_logs(LL_ERROR, LP_DATETIME, "Received SEGV signal, quitting..."); // Log any signal that causes exit
	exit(EXIT_FAILURE);
}

#if !defined(_WIN32) && !defined(_WIN64)
void sigchld_handler(int sig) {
	my_logs(LL_VERBOSE, LP_DATETIME, "Received CHLD signal, reaping...");
	while (waitpid(-1, NULL, WNOHANG) > 0) { ; }
}
#endif

//
// Manage errors with provided options
//
void option_error(const char *s) {
	fprintf(stderr, s, NULL);
	fprintf(stderr, "\nTry `" PACKAGE_NAME " --help' for more information.\n");
	exit(EXIT_FAILURE);
}

//
// Print a small help screen
//
void printhelp() {
	printf("Usage: " PACKAGE_NAME " -s server[:port] -p port [options...]\n\n");
	printf("Accept incoming connections and redirect them to the specified server.\n\n");
	printf("  -h  --help          Display this help text\n");
	printf("  -v  --version       Display version information and exit\n");
	printf("  -V  --verbose       Be more talkative\n");
	printf("      --minimal-log   Don't log data, only connection info\n");
	printf("  -q  --quiet         Be less talkative\n");
	printf("  -s  --server        Server to connect to, syntax: server_name:port\n");
	printf("  -m  --mirror        Mirror mode. Don't connect to a server,\n");
	printf("                      simply send back received bytes to the client.\n");
	printf("                      Assumed if no server is provided.\n");
	printf("  -p  --listen-port   Port to listen to, it is the server port by default\n");
	printf("  -r  --run-once      Do one run and exit\n");
	printf("  -t  --telnet        Log trafic assuming data is telnet-style\n");
	printf("  -b  --bufsize       Size of buffer in bytes for network data (default: %u)\n", DEFAULT_BUFFER_SIZE);
	printf("      --timeout       Timeout in seconds to connect to server (default: %i)\n", DEFAULT_CONNECT_TIMEOUT);
	printf("      --ip-as-port    Use last byte of IP to form source port when connecting to server:\n");
	printf("                      Try up to 252 times using this formula (where ipa is the last\n");
	printf("                      IP byte): p = 1024 + (256 * n) + ipa\n");
	printf("      --connexe       Fork an external program for every new connection\n");
	printf("                      Command will have client IP address passed as argment\n");
	printf("  -l  --log-file      Log file (default: %s)\n", DEFAULT_LOGFILE);
	printf("      --rotate-log    Rotate log files adding .n to name and cycling through files\n");
	printf("                      Off by default.\n");
	printf("      --rotate-log-size-kb  Total size of log files when --rotate-log is used\n");
	printf("                            %lu by default.\n", (long unsigned)DEFAULT_ROTATE_LOG_SIZE_KB);
	printf("      --rotate-log-nb-files Number of files to cycle through when --rotate-log\n");
	printf("                            is used. %d by default.\n", DEFAULT_ROTATE_LOG_NB_FILES);
	printf("  -n  --nodisplay-log Don't print the log on the screen\n");
}

//
// Print version information
//
void printversion() {
	printf(PACKAGE_STRING "\n");
	printf("Copyright 2012, 2013, 2014 Sébastien Millet\n");
	printf("This program is free software; you may redistribute it under the terms of\n");
	printf("the GNU General Public License version 3 or (at your option) any later version.\n");
	printf("This program has absolutely no warranty.\n");
}

//
// Check bounds of an integer-like value, as part of options parsing
//
#define CHECK_BOUNDS_FUNC_CREATE(t, fmt) \
void check_bounds_##t(const t v, const int check_min, const t val_min, const int check_max, const t val_max, const char *err) { \
	char e[REGULAR_STR_STRBUFSIZE]; \
	char m[100]; \
	snprintf(e, sizeof(e), "%s (value = " fmt, err, v); \
	if (check_min) { \
		snprintf(m, sizeof(m), ", min = " fmt, val_min); \
		strlcat(e, m, sizeof(e)); \
	} \
	if (check_max) { \
		snprintf(m, sizeof(m), ", max = " fmt, val_max); \
		strlcat(e, m, sizeof(e)); \
	} \
	strlcat(e, ")", sizeof(e)); \
	if ((check_min && v < val_min) || (check_max && v > val_max)) { \
		option_error(e); \
	} \
}
CHECK_BOUNDS_FUNC_CREATE(int, "%d");
CHECK_BOUNDS_FUNC_CREATE(ssize_t, "%li");

void parse_options(int argc, char *argv[]) {

	static struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'v'},
		{"verbose", no_argument, NULL, 'V'},
		{"quiet", no_argument, NULL, 'q'},
		{"minimal-log", no_argument, NULL, 2},
		{"ip-as-port", no_argument, NULL, 3},
		{"connexe", required_argument, NULL, 4},
		{"test-mode", required_argument, NULL, 5},
		{"server", required_argument, NULL, 's'},
		{"mirror", no_argument, NULL, 'm'},
		{"listen-port", required_argument, NULL, 'p'},
		{"telnet", no_argument, NULL, 't'},
		{"bufsize", required_argument, NULL, 'b'},
		{"timeout", required_argument, NULL, 1},
		{"log-file", required_argument, NULL, 'l'},
		{"nodisplay-log", no_argument, NULL, 'n'},
		{"run-once", no_argument, NULL, 'r'},
		{"rotate-log", no_argument, NULL, 6},
		{"rotate-log-size-kb", required_argument, NULL, 7},
		{"rotate-log-nb-files", required_argument, NULL, 8},
		{0, 0, 0, 0}
	};

	int c;
	int option_index = 0;

	char *pos;

	int server_name_set = FALSE;
	int server_port_set = FALSE;
	int listen_port_set = FALSE;

	strlcpy(opt_logfile, DEFAULT_LOGFILE, sizeof(opt_logfile)); // NOTE: BSD strlcpy safer than strncpy

	while (1) {

		c = getopt_long(argc, argv, "hvs:p:tb:l:nVqrm", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {

			case 'h':
				printhelp();
				exit(EXIT_FAILURE);

			case 'v':
				printversion();
				exit(EXIT_FAILURE);

			case 's':
				pos = strrchr(optarg, ':');
				if (pos == NULL) {
					strlcpy(opt_server_name, optarg, sizeof(opt_server_name)); // NOTE: BSD strlcpy safer than strncpy
				} else {
					size_t n = (size_t)(pos - optarg);
					if (n > sizeof(opt_server_name) - 1) {
						n = sizeof(opt_server_name) - 1;
					}
					strlcpy(opt_server_name, optarg, n+1); // NOTE: BSD strlcpy safer than strncpy
					opt_server_port = atoi(pos + 1);
					server_port_set = TRUE;
				}
				server_name_set = TRUE;
				break;

			case 'm':
				opt_mirror_mode = TRUE;
				break;

			case 'p':
				opt_listen_port = atoi(optarg);
				listen_port_set = TRUE;
				break;

			case 't':
				opt_telnet_log = TRUE;
				break;

			case 'b':
				opt_bufsize = strtol(optarg, NULL, 0);
				break;

			case 1:
				opt_connect_timeout = atoi(optarg);
				break;

			case 2:
				opt_minimal_log = TRUE;
				break;

			case 3:
				opt_ip_as_port = TRUE;
				break;

			case 4: // connexe
				strlcpy(opt_connexe, optarg, sizeof(opt_connexe)); // NOTE: BSD strlcpy safer than strncpy
				break;

			case 5:
				opt_test_mode = atoi(optarg);
				break;

			case 6:
				opt_rotate_log = TRUE;
				break;

			case 7:
				opt_rotate_log_size_kb = strtol(optarg, NULL, 0);
				break;

			case 8:
				opt_rotate_log_nb_files = atoi(optarg);
				break;

			case 'l':
				strlcpy(opt_logfile, optarg, sizeof(opt_logfile)); // NOTE: BSD strlcpy safer than strncpy
				break;

			case 'n':
				opt_display_log = FALSE;
				break;

			case 'V':
				opt_current_log_level++;
				break;

			case 'q':
				opt_current_log_level--;
				break;

			case 'r':
				opt_run_once = TRUE;
				break;

			case '?':
				exit(EXIT_FAILURE);

			default:
				abort();
		}
	}
	if (optind < argc)
		option_error("Trailing options");
	if (server_name_set && opt_mirror_mode)
		option_error("You can use only one of --server and --mirror options at a time");
	if (!opt_mirror_mode && !listen_port_set && !server_port_set)
		option_error("You musy specify a port with option --listen-port or in the server name (--server server_name:port)");
	if (!server_name_set)
		opt_mirror_mode = TRUE;
	if (opt_mirror_mode && !listen_port_set)
		option_error("In mirror mode, you must specify a port with option --listen-port");
	opt_listen_port = (listen_port_set ? opt_listen_port : opt_server_port);
	opt_server_port = (server_port_set ? opt_server_port : opt_listen_port);
	check_bounds_int(opt_server_port, TRUE, 1, FALSE, 0, "Illegal server port value");
	check_bounds_int(opt_listen_port, TRUE, 1, FALSE, 0, "Illegal listen port value");
	check_bounds_ssize_t(opt_bufsize, TRUE, 1, FALSE, 0, "Illegal buffer size value");
	check_bounds_int(opt_connect_timeout, TRUE, 1, FALSE, 0, "Illegal timeout value");
	if (opt_rotate_log) {
		check_bounds_ssize_t(opt_rotate_log_size_kb, TRUE, MIN_ROTATE_LOG_SIZE_KB,
			TRUE, MAX_ROTATE_LOG_SIZE_KB, "Illegal --rotate-log-size-bytes value");
		check_bounds_int(opt_rotate_log_nb_files, TRUE, 1,
			TRUE, MAX_ROTATE_LOG_NB_FILES, "Illegal --rotate-log-nb-files value");
	}
	if (opt_current_log_level < LL_ERROR)
		opt_current_log_level = LL_ERROR;
	if (opt_current_log_level > LL_DEBUG)
		opt_current_log_level = LL_DEBUG;
}

int main(int argc, char *argv[]) {

	parse_options(argc, argv);
	g_telnet_str_bufsize = 2 * (size_t)opt_bufsize + 3;

	atexit(atexit_handler);
	signal(SIGTERM, sigterm_handler);
	signal(SIGABRT, sigabrt_handler);
	signal(SIGINT,  sigint_handler);
	signal(SIGSEGV, sigsegv_handler);
#if !defined(_WIN32) && !defined(_WIN64)
	signal(SIGCHLD, sigchld_handler);
#endif

	if (!opt_test_mode) {
		my_logs(LL_ERROR, LP_DATETIME, PACKAGE_STRING " start"); // Always log the important event of starting
	} else {
			// Don't log program version in test mode, to avoid useless output changes (in test suite) when version changes
		my_logs(LL_ERROR, LP_DATETIME, PACKAGE_NAME " start"); // Always log the important event of starting
	}

		// Just to call WSAStartup...
	os_init_network();

	memset(g_connection_socks,-1,sizeof(g_connection_socks));
	memset(g_session_socks,-1,sizeof(g_session_socks));

	almost_neverending_loop();

	if (g_quitting)
		return EXIT_FAILURE;
	g_quitting = TRUE;

	my_logs(LL_ERROR, LP_DATETIME, PACKAGE_NAME " end"); // Always log the important event of ending
	my_logs(LL_ERROR, LP_NOTHING, "");
	my_log_close();

	return EXIT_SUCCESS;
}

