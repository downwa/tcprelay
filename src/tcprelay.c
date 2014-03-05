// tcprelay.c

// Copyright Sébastien Millet, 2012

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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include <signal.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>

loglevel_t current_log_level = LL_NORMAL;

const char *DEFAULT_LOGFILE = PACKAGE_TARNAME ".log";
const char *SRV_SHORTNAME = "[SRV]";
const char *CLI_SHORTNAME = "[CLI]";
const char *PREFIX_RECEIVED = "<<< ";
const char *PREFIX_SENT = ">>> ";

char server_name[300];
char logfile[1000];

int server_port = 0;
int listen_port = 0;
size_t bufsize = DEFAULT_BUFFER_SIZE;
int connect_timeout = DEFAULT_CONNECT_TIMEOUT;
int telnet_log = FALSE;
int display_log = TRUE;
int run_once = FALSE;
int g_mirror_mode = FALSE;
int minimal_log = FALSE; // Turn off data logging
int ip_as_port = FALSE; // Last byte of IP address used to form source port: Try up to 252 times using this formula (where ipa is the last IP byte): p=1024+(256*n)+ipa

FILE *log_fd;

int flag_interrupted = FALSE;
int quitting = FALSE;

int g_listen_sock;
int g_connection_socks[MAXSESSIONS];
int g_session_socks[MAXSESSIONS];
struct telnet_t telnet[MAXSESSIONS][2];
char* buffer[MAXSESSIONS];
int connection_cli_is_live[MAXSESSIONS],connection_srv_is_live[MAXSESSIONS];
size_t telnet_str_bufsize;
int bport[MAXSESSIONS];

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
/************************************************************************************************************/
/* OS SOCKETS                                                                                               */
/************************************************************************************************************/

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

#endif


/************************************************************************************************************/
/* LOGGING                                                                                                  */
/************************************************************************************************************/
//
// Print an error in standard error and exit program
// if exit_program is true.
//
void fatal_error(const char *format, ...) {
  va_list args;
  va_start(args, format);

  char str[REGULAR_STR_STRBUFSIZE];
  vsnprintf(str, REGULAR_STR_STRBUFSIZE, format, args);
  strlcat(str, "\n", REGULAR_STR_STRBUFSIZE); // NOTE: BSD strlcat is safer than strncat
  fprintf(stderr, str, NULL);
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
  log_fd = fopen(logfile, "a");
}

//
// Closes the program log
//
void my_log_close() {
  fclose(log_fd);
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

//
// Output log string, used by my_log only
//
void my_log_core_output(const char *s) {
  fputs(s, log_fd);
  fputs("\n", log_fd);
  fflush(log_fd);
  if (display_log) {
    puts(s);
  }
  fflush(stdout);
}

//
// Output a string in the program log
//
void my_logs(const loglevel_t log_level, const logdisp_t log_disp, const char *s) {
  if (log_level > current_log_level)
    return;

  char dt[REGULAR_STR_STRBUFSIZE];

  my_log_core_get_dt_str(log_disp, dt, REGULAR_STR_STRBUFSIZE);
  strlcat(dt, s, REGULAR_STR_STRBUFSIZE); // NOTE: BSD strlcat is safer than strncat
  dt[REGULAR_STR_STRBUFSIZE-1]=0;         // NOTE: Should always null-terminate (truncate) (not guaranteed otherwise)
  my_log_core_output(dt);

}

//
// Output a formatted string in the program log
//
void my_logf(const loglevel_t log_level, const logdisp_t log_disp, const char *format, ...) {
  va_list args;
  va_start(args, format);

  if (log_level > current_log_level)
    return;

  char dt[REGULAR_STR_STRBUFSIZE];
  char str[REGULAR_STR_STRBUFSIZE];

  my_log_core_get_dt_str(log_disp, dt, REGULAR_STR_STRBUFSIZE);

  vsnprintf(str, REGULAR_STR_STRBUFSIZE, format, args);
  strlcat(dt, str, REGULAR_STR_STRBUFSIZE); // NOTE: BSD strlcat is safer than strncat
  dt[REGULAR_STR_STRBUFSIZE-1]=0;           // NOTE: Should always null-terminate (truncate) (not guaranteed otherwise)
  my_log_core_output(dt);

  va_end(args);
}

//
// Log a telnet line
//
void my_log_telnet(const int is_received, const char *s) {
  if(minimal_log) { return; }
  char prefix[50];
  strlcpy(prefix, is_received ? PREFIX_RECEIVED : PREFIX_SENT, sizeof(prefix)); // NOTE: BSD strlcpy safer than strncpy
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
void my_log_buffer(const char *buffer, const unsigned int nb_bytes, int *telnet_ok) {
  if(minimal_log) { return; }
  char s[hexline_strbufsize];
  unsigned int nb_on_line;

  unsigned int offset;
  for (offset = 0; offset < nb_bytes; offset += 16) {
    nb_on_line = nb_bytes - offset;
    if (nb_on_line > 16) {
      nb_on_line = 16;
    }
    get_hex_line(buffer, offset, nb_on_line, s, hexline_strbufsize, telnet_ok);
    my_logs(LL_NORMAL, LP_2SPACE, s);
  }
}

/************************************************************************************************************/
/* SESSION UTILITIES                                                                                        */
/************************************************************************************************************/
void shutdownFd(int current_fd) {
  int xa;
  for(xa=0; xa<MAXSESSIONS; xa++) {
    if(connection_cli_is_live[xa] || connection_srv_is_live[xa]) {
      if(closeSession(xa, current_fd)) { break; }
    }
  }
}

int closeSession(int session_nr, int current_fd) {
  int doBreak=FALSE;
  if (current_fd == g_connection_socks[session_nr]) {
    shutdown(g_connection_socks[session_nr],SHUT_RD); connection_cli_is_live[session_nr]=FALSE; doBreak=TRUE;
  }
  if (current_fd == g_session_socks[session_nr]) {
    shutdown(g_session_socks[session_nr],SHUT_RD); connection_srv_is_live[session_nr]=FALSE; doBreak=TRUE; 
  }
  // NOTE: Close both sockets only when other end of both sockets has performed an orderly shutdown
  if(!connection_cli_is_live[session_nr] && !connection_srv_is_live[session_nr]) {
    if(g_connection_socks[session_nr] != -1) { os_closesocket(g_connection_socks[session_nr]); g_connection_socks[session_nr]=-1; }
    if(g_session_socks[session_nr] != -1)    { os_closesocket(g_session_socks[session_nr]);    g_session_socks[session_nr]=-1;    }
    // Free allocated memory
    free(buffer[session_nr]); buffer[session_nr]=NULL;
    int it;
    for (it = 0; it < 2; it++) { free(telnet[session_nr][it].base); telnet[session_nr][it].base=NULL; }
  }
  return doBreak;
}  

// Find an available session (one that has both sockets closed
int alloc_session() {
  int xa;
  for(xa=0; xa<MAXSESSIONS; xa++) {
    if(g_connection_socks[xa] == -1 && g_session_socks[xa] == -1) { return xa; }
  }
  return -1;
}

  // String to store error descriptions
char s_err[ERR_STR_BUFSIZE];
  // String to print the description of the target server, like "servername:port"
char server_desc[200];
  // Resolving server name
struct sockaddr_in server;
struct hostent *hostinfo = NULL;

int newSession() {
  struct sockaddr_in client;
  unsigned int client_size = sizeof(client);
  int session_nr=alloc_session();
  // 1. Accept an incoming connection
  my_logf(LL_DEBUG, LP_DATETIME, "Session %d accepting on port %i...", session_nr, listen_port);
  if ((g_session_socks[session_nr] = accept(g_listen_sock, (struct sockaddr *) &client, &client_size)) == ACCEPT_ERROR) {
    if (flag_interrupted) { return -1; } // Cancel new session
    my_logf(LL_ERROR, LP_DATETIME, "accept() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
    return -1;
  }
  my_logf(LL_NORMAL, LP_DATETIME, "Accepted connection from %s: session_nr=%d", inet_ntoa(client.sin_addr), session_nr/*g_session_socks[session_nr]*/);
  if(ip_as_port) {
    char *pp=strrchr(inet_ntoa(client.sin_addr),'.');
    bport[session_nr]=0;
    if(pp) { bport[session_nr]=atoi(&pp[1]); }
  }
  // 2. Connect to remote server
  if (g_mirror_mode) {
    g_connection_socks[session_nr] = -1;
  } else {
    if ((g_connection_socks[session_nr] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_ERROR) {
      fatal_error("socket() error to create connection socket, %s", os_last_err_desc(s_err, sizeof(s_err)));
    }
    server.sin_family = AF_INET;
    server.sin_port = htons((uint16_t)server_port);
    server.sin_addr = *(struct in_addr *)hostinfo->h_addr;
    my_logf(LL_VERBOSE, LP_DATETIME, "Connecting to %s...", server_desc);
    // tv value is undefined after call to connect() as per documentation, so
    // it is to be re-set every time.
    struct timeval tv; // time value    
    tv.tv_sec = connect_timeout;
    tv.tv_usec = 0;
    if (connect_with_timeout(&server, &g_connection_socks[session_nr], &tv, server_desc, session_nr) != 0) {
      os_closesocket(g_session_socks[session_nr]); g_session_socks[session_nr]=-1;
      return -1;
    }
    my_logf(LL_NORMAL, LP_DATETIME, "Connected to %s: session_nr=%d", server_desc, session_nr/*_connection_socks[session_nr]*/);
  }
  // Prepare resources to manage relaying: buffer to exchange data through the network
  // (buffer), and strings to log trafic in telnet-style.
  buffer[session_nr] = (char *)malloc(bufsize);
  int it;
  for (it = 0; it < 2; it++) {
    telnet[session_nr][it].base = (char *)malloc(telnet_str_bufsize);
    telnet[session_nr][it].write = telnet[session_nr][it].base;
    telnet[session_nr][it].nb_chars = 0;
    telnet[session_nr][it].last_cr = FALSE;
  }
  
  return session_nr;
}

/* bindPort purpose: Bind to a local port as a method of communicating to the receiver what the source ip
 * address is.  The receiver (server) can use the source port MOD 256 minus 1024 to determine the last
 * byte of the 4 byte IP address (the other three bytes must be assumed to be on the same "class C" network)
 */
void bindPort(int session_nr) {
  int sport=-1;
  // Optionally try to use last byte of client IP address as source port when connecting to server
  // Try up to 252 times using this formula (where ipa is the last IP byte): p=1024+(256*n)+ipa
  // This can be useful for server to know which client connected to it
  if(ip_as_port) {
    int myport=bport[session_nr]+1024;
    
    int on = 1;
    for(sport=myport; sport<65535; sport+=256) {
      struct sockaddr_in sname;
      sname.sin_family = AF_INET;
      sname.sin_addr.s_addr = htonl(INADDR_ANY);
      sname.sin_port = htons((uint16_t)sport);
      if (bind(g_connection_socks[session_nr], (struct sockaddr *)&sname, sizeof(sname)) == SOCKET_ERROR) {
	if(errno == EADDRINUSE) { 
	  my_logf(LL_DEBUG, LP_DATETIME, "bind() trying again, %s", os_last_err_desc(s_err, sizeof(s_err)));	  
	  continue; }
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
int connect_with_timeout(const struct sockaddr_in *server, int *connection_sock, struct timeval *tv, const char *desc, int session_nr) {
  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(*connection_sock, &fdset);

  os_set_sock_nonblocking_mode(*connection_sock);

  bindPort(session_nr);

  int res = 0;
  if (connect(*connection_sock, (struct sockaddr *)server, sizeof(*server)) == CONNECT_ERROR) {
    if (os_last_network_op_is_in_progress()) {
      if (select((*connection_sock) + 1, NULL, &fdset, NULL, tv) <= 0) {
        my_logf(LL_ERROR, LP_DATETIME, "Timeout connecting to %s, %s", desc, os_last_err_desc(s_err, sizeof(s_err)));
        res = 1;
      } else {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(*connection_sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
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
/************************************************************************************************************/
/* MAIN LOOP                                                                                                */
/************************************************************************************************************/

// NOTE: Added multiplexing of connections so several connections can be relayed simultaneously

//
// Main loop
//
void almost_neverending_loop() {
  if (g_mirror_mode) {
    my_logf(LL_VERBOSE, LP_DATETIME, "Mode: mirror");
    my_logf(LL_VERBOSE, LP_DATETIME, "Server: n/a");
    my_logf(LL_VERBOSE, LP_DATETIME, "Server port: n/a");
  } else {
    my_logf(LL_VERBOSE, LP_DATETIME, "Mode: connection to server");
    my_logf(LL_VERBOSE, LP_DATETIME, "Server: %s", server_name);
    my_logf(LL_VERBOSE, LP_DATETIME, "Server port: %i", server_port);
  }
  my_logf(LL_VERBOSE, LP_DATETIME, "Listening port: %u", listen_port);
  my_logf(LL_VERBOSE, LP_DATETIME, "log file: %s", logfile);
  my_logf(LL_VERBOSE, LP_DATETIME, "Display log: %s", display_log ? "yes" : "no");
  my_logf(LL_VERBOSE, LP_DATETIME, "Telnet log: %s", telnet_log ? "yes" : "no");
  my_logf(LL_VERBOSE, LP_DATETIME, "Buffer size: %u", bufsize);
  my_logf(LL_VERBOSE, LP_DATETIME, "Connection timeout: %i", connect_timeout);
  my_logf(LL_VERBOSE, LP_DATETIME, "Run once: %s", run_once ? "yes" : "no");
  my_logf(LL_VERBOSE, LP_DATETIME, "Log level: %i", current_log_level);

  snprintf(server_desc, 200, "%s:%i", server_name, server_port);

    // Short string to print the name of the connecting point a packet was received from
  char i_name[50];

  if (!g_mirror_mode) {
    my_logf(LL_DEBUG, LP_DATETIME, "Running gethosbyname() on %s", server_name);
    hostinfo = gethostbyname(server_name);
    if (hostinfo == NULL) {
      fatal_error("Unknown host %s, %s", server_name, os_last_err_desc(s_err, sizeof(s_err)));
    }
  }

    // Putting in place listening socket
  if ((g_listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_ERROR) {
    fatal_error("socket() error to create listening socket, %s", os_last_err_desc(s_err, sizeof(s_err)));
  }
  int on = 1;
  if (setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == SETSOCKOPT_ERROR) {
    fatal_error("setsockopt() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
  }

  struct sockaddr_in name;
  name.sin_family = AF_INET;
  name.sin_addr.s_addr = htonl(INADDR_ANY);
  name.sin_port = htons((uint16_t)listen_port);
  if (bind(g_listen_sock, (struct sockaddr *)&name, sizeof(name)) == SOCKET_ERROR) {
    fatal_error("bind() error on listening socket, %s", os_last_err_desc(s_err, sizeof(s_err)));
  }
  if (listen(g_listen_sock, 1) == LISTEN_ERROR) {
    fatal_error("listen() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
  }


  int fdmax;
  int current_fd;

  fd_set fdset;

  int telnet_max_line_size_hit;

  char mystring[500];

  ssize_t nb_bytes_received;
  ssize_t nb_bytes_sent;
  int resend_sock;
  int warned_buffer_too_small;
  int telnet_ok;

  do {
    telnet_ok = TRUE;
    telnet_max_line_size_hit = FALSE;
    warned_buffer_too_small = FALSE;
    
    /** Add all sockets to fdset (including listen socket, to be notified of new connections) **/
    FD_ZERO(&fdset);
    FD_SET(g_listen_sock, &fdset);
    int fdmax=g_listen_sock;
    int xa;
    for(xa=0; xa<MAXSESSIONS; xa++) { // Add all active sockets
      if(g_connection_socks[xa] > -1)    {
	FD_SET(g_connection_socks[xa], &fdset); my_logf(LL_DEBUG, LP_DATETIME, "Watching conn fd %d",g_connection_socks[xa]);
      }
      if(g_session_socks[xa] > -1)       {
	FD_SET(g_session_socks[xa], &fdset); my_logf(LL_DEBUG, LP_DATETIME, "Watching sess fd %d",g_session_socks[xa]);
      }
      if(g_connection_socks[xa] > fdmax) { fdmax=g_connection_socks[xa]; }
      if(g_session_socks[xa] > fdmax)    { fdmax=g_session_socks[xa];    }
    }
    my_logf(LL_DEBUG, LP_DATETIME, "select wait fdmax+1=%d",fdmax+1);
    int ret=select(fdmax + 1, &fdset, NULL, NULL, NULL);
    if (ret == SELECT_ERROR) {
      fatal_error("select() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
    }
    my_logf(LL_DEBUG, LP_DATETIME, "select:activity on %d fds...",ret);
    
    int session_nr=-1; // Which session is demanding attention
    // 3. Loop through both connections of all sessions to forward received data back and forth
    for (current_fd = 0; current_fd <= fdmax && !flag_interrupted; current_fd++) {
      if (!FD_ISSET(current_fd, &fdset)) { continue; }
      my_logf(LL_DEBUG, LP_DATETIME, "current_fd=%d",current_fd);
      if(current_fd == g_listen_sock) {
	session_nr=newSession();
	if(session_nr == -1) {
	  if (flag_interrupted) { break; } // Cancel new session
	  continue;
	}
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
      if (!g_mirror_mode && current_fd == g_connection_socks[session_nr]) {
	snprintf(i_name,sizeof(i_name),"%s[%d]",SRV_SHORTNAME,session_nr);
      } else if (current_fd == g_session_socks[session_nr]) {
	snprintf(i_name,sizeof(i_name),"%s[%d]",CLI_SHORTNAME,session_nr);
      } else {
	fatal_error("Internal error never_ending_loop()-01, file %s, line %lu: activity on unexpected fd=%d (listen=%d)",  __FILE__, __LINE__,current_fd,g_listen_sock);
	//internal_error("never_ending_loop()-01: activity on unexpected fd=%d (listen=%d)", __FILE__, __LINE__,current_fd,g_listen_sock);
      }
      if ((nb_bytes_received = recv(current_fd, buffer[session_nr], bufsize, 0)) == RECV_ERROR) {
	my_logf(LL_ERROR, LP_DATETIME, "%s: recv() error, %s", i_name, os_last_err_desc(s_err, sizeof(s_err)));
	closeSession(session_nr, current_fd);
      } else if (nb_bytes_received == 0) {
	my_logf(LL_NORMAL, LP_DATETIME, "%s: closed connection", i_name);
	closeSession(session_nr, current_fd);
      } else {
	if (nb_bytes_received == (ssize_t)bufsize && !warned_buffer_too_small) {
	  my_logf(LL_WARNING, LP_DATETIME, "%s: recv() buffer size hit (size=%i)", i_name, bufsize);
	  warned_buffer_too_small = TRUE;
	}
	if (telnet_log) {
	  int it = (current_fd == g_session_socks[session_nr] ? 0 : 1);
	  char c;
	  int bufwalker;
	  for (bufwalker = 0; bufwalker < nb_bytes_received; bufwalker++) {
	    c = buffer[session_nr][bufwalker];
	    if (c == '\n' && telnet[session_nr][it].last_cr) {
	      *(telnet[session_nr][it].write - 1) = '\0';
	      my_log_telnet(!g_mirror_mode && current_fd == g_connection_socks[session_nr], telnet[session_nr][it].base);
	      telnet[session_nr][it].write = telnet[session_nr][it].base;
	      telnet[session_nr][it].nb_chars = 0;
	    } else {
	      if ((size_t)telnet[session_nr][it].nb_chars >= telnet_str_bufsize - 1) {
		*(telnet[session_nr][it].write) = '\0';
		my_log_telnet(!g_mirror_mode && current_fd == g_connection_socks[session_nr], telnet[session_nr][it].base);
		telnet[session_nr][it].write = telnet[session_nr][it].base;
		telnet[session_nr][it].nb_chars = 0;
		if (!telnet_max_line_size_hit) {
		  my_logf(LL_WARNING, LP_DATETIME,
			  "%s: telnet max line size hit, consider increasing it by increasing the buffer size", i_name);
		  telnet_max_line_size_hit = TRUE;
		}
	      }
	      *(telnet[session_nr][it].write) = c;
	      telnet[session_nr][it].write++;
	      telnet[session_nr][it].nb_chars++;
	    }
	    telnet[session_nr][it].last_cr = (c == '\r');
	    if (telnet_ok && c < 32 && (c != '\r' && c != '\n' && !isspace(c))) {
	      my_logs(LL_WARNING, LP_DATETIME, "Unprintable character encountered although --telnet option in use");
	      telnet_ok = FALSE;
	    }
	  }
	} else {
	  snprintf(mystring, sizeof(mystring), "%s sent %li bytes (0x%04X)", i_name, nb_bytes_received, (unsigned int)nb_bytes_received);
	  my_logs(LL_NORMAL, LP_DATETIME, mystring);
	  my_log_buffer(buffer[session_nr], (unsigned int)nb_bytes_received, &telnet_ok);
	}
	if (g_mirror_mode) {
	  resend_sock = g_session_socks[session_nr];
	} else {
	  resend_sock = (current_fd == g_session_socks[session_nr] ? g_connection_socks[session_nr] : g_session_socks[session_nr]);
	}
	
	//my_logf(LL_DEBUG, LP_DATETIME, "Will forward TCP data to alternate peer, size: %li", (unsigned int)nb_bytes_received);
	int ofs=0;
	size_t len=(size_t)nb_bytes_received;
	dosend:
	my_logf(LL_DEBUG, LP_DATETIME, "Will forward TCP data to alternate peer %d, size: %li", resend_sock, (unsigned int)len);
	if ((nb_bytes_sent = send(resend_sock, &buffer[session_nr][ofs], len, 0)) == SEND_ERROR) {
	  my_logf(LL_ERROR, LP_DATETIME, "send() error, %s", os_last_err_desc(s_err, sizeof(s_err)));
	  closeSession(session_nr, current_fd);
	} else if (nb_bytes_sent == 0) {
	  my_logs(LL_ERROR, LP_DATETIME, "send() error, no byte sent");
	} else if (nb_bytes_sent != nb_bytes_received) {
	  // FIXME
	  // Maybe the TCP layer is requesting the code to do other send(),
	  // to reach, after as many send() as necessary, the total number
	  // of bytes received? Any way.
	  my_logf(LL_ERROR, LP_DATETIME, "Could not send as many bytes as received (received=%lu, sent=%lu",
		  (long unsigned int)nb_bytes_received, (long unsigned int)nb_bytes_sent);
	  // NOTE: Above fixme is correct and below change should fix it but needs to be tested
	  ofs+=nb_bytes_sent; len=-nb_bytes_sent;
	  goto dosend;
	}
      }
    } // END for(current_fd)
    
    if (!telnet_log && telnet_ok && !minimal_log) {
      my_logs(LL_WARNING, LP_DATETIME, "All characters received were printable, consider using option --telnet");
    }
    int it;
    for (it = 0; it < 2; it++) {
      if (telnet[session_nr][it].nb_chars >= 1) {
	my_logf(LL_WARNING, LP_DATETIME,
		"%s: pending characters not terminated by internet new line", (it == 0 ? CLI_SHORTNAME : SRV_SHORTNAME));
	*(telnet[session_nr][it].write) = '\0';
	my_log_telnet(it == 1, telnet[session_nr][it].base);
      }
    }
  } while (!run_once);
  
  os_closesocket(g_listen_sock); g_listen_sock=-1;
}

/************************************************************************************************************/
/************************************************************************************************************/
/************************************************************************************************************/

//
// Manage atexit()
//
void atexit_handler() {
  if (quitting)
    return;
  quitting = TRUE;

  int xa;
  for(xa=0; xa<MAXSESSIONS; xa++) {
    if(g_connection_socks[xa] != -1) { os_closesocket(g_connection_socks[xa]); g_connection_socks[xa]=-1; }
    if(g_session_socks[xa] != -1)    { os_closesocket(g_session_socks[xa]);    g_session_socks[xa]=-1; }
  }

  os_closesocket(g_listen_sock); g_listen_sock=-1;

  my_logs(LL_NORMAL, LP_DATETIME, PACKAGE_NAME " stop");
  my_logs(LL_NORMAL, LP_NOTHING, "");
  my_log_close();
}

//
// Manage signals
//
void sigterm_handler(int sig) {
  flag_interrupted = TRUE;
  my_logs(LL_VERBOSE, LP_DATETIME, "Received TERM signal, quitting...");
  exit(EXIT_FAILURE);
}

void sigabrt_handler(int sig) {
  flag_interrupted = TRUE;
  my_logs(LL_VERBOSE, LP_DATETIME, "Received ABORT signal, quitting...");
  exit(EXIT_FAILURE);
}

void sigint_handler(int sig) {
  flag_interrupted = TRUE;
  my_logs(LL_VERBOSE, LP_DATETIME, "Received INT signal, quitting...");
  exit(EXIT_FAILURE);
}

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
  printf("Accept an incoming connection and redirect it to the specified server.\n\n");
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
  printf("                      Try up to 252 times using this formula (where ipa is the last IP byte): p=1024+(256*n)+ipa\n");
  printf("  -l  --log-file      Log file (default: %s)\n", DEFAULT_LOGFILE);
  printf("  -n  --nodisplay-log Don't print the log on the screen\n");
}

//
// Print version information
//
void printversion() {
  printf(PACKAGE_STRING "\n");
  printf("Copyright 2012 Sébastien Millet\n");
	printf("This program is free software; you may redistribute it under the terms of\n");
	printf("the GNU General Public License version 3 or (at your option) any later version.\n");
	printf("This program has absolutely no warranty.\n");
}

//
// Check bounds of an integer, as part of options parsing
//
void check_bounds(const int v, const int check_min, const int val_min, const int check_max, const int val_max, const char *err) {
  if ((check_min && v < val_min) || (check_max && v > val_max)) {
    option_error(err);
  }
}

void parse_options(int argc, char *argv[]) {

  static struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"verbose", no_argument, NULL, 'V'},
    {"quiet", no_argument, NULL, 'q'},
    {"minimal-log", no_argument, NULL, 2}, 
    {"ip-as-port", no_argument, NULL, 3},    
    {"server", required_argument, NULL, 's'},
    {"mirror", no_argument, NULL, 'm'},
    {"listen-port", required_argument, NULL, 'p'},
    {"telnet", no_argument, NULL, 't'},
    {"bufsize", required_argument, NULL, 'b'},
    {"timeout", required_argument, NULL, 1},
    {"log-file", required_argument, NULL, 'l'},
    {"nodisplay-log", no_argument, NULL, 'n'},
    {"run-once", no_argument, NULL, 'r'},
    {0, 0, 0, 0}
  };

  int c;
  int option_index = 0;

  int ii;

  char *pos;

  int server_name_set = FALSE;
  int server_port_set = FALSE;
  int listen_port_set = FALSE;

  strlcpy(logfile, DEFAULT_LOGFILE, sizeof(logfile)); // NOTE: BSD strlcpy safer than strncpy

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
          strlcpy(server_name, optarg, sizeof(server_name)); // NOTE: BSD strlcpy safer than strncpy
        } else {
          size_t n = (size_t)(pos - optarg);
          if (n > sizeof(server_name) - 1) {
            n = sizeof(server_name) - 1;
          }
          strlcpy(server_name, optarg, n+1); // NOTE: BSD strlcpy safer than strncpy
          server_port = atoi(pos + 1);
          server_port_set = TRUE;
        }
        server_name_set = TRUE;
        break;
      
      case 'm':
        g_mirror_mode = TRUE;
        break;

      case 'p':
        listen_port = atoi(optarg);
        listen_port_set = TRUE;
        break;

      case 't':
        telnet_log = TRUE;
        break;

      case 'b':
        ii = atoi(optarg);
        if (ii < 0)
          ii = 0;
        bufsize = (size_t)ii;
        break;

      case 1:
        connect_timeout = atoi(optarg);
        break;

      case 2:
        minimal_log = TRUE;
        break;

      case 3:
        ip_as_port = TRUE;
        break;
      
      case 'l':
        strlcpy(logfile, optarg, sizeof(logfile)); // NOTE: BSD strlcpy safer than strncpy
        break;

      case 'n':
        display_log = FALSE;
        break;

      case 'V':
        current_log_level++;
        break;

      case 'q':
        current_log_level--;
        break;

      case 'r':
        run_once = TRUE;
        break;

      case '?':
        exit(EXIT_FAILURE);

      default:
        abort();
    }
  }
  if (optind < argc)
    option_error("Trailing options");
  if (server_name_set && g_mirror_mode)
    option_error("You can use only one of --server and --mirror options at a time");
  if (!g_mirror_mode && !listen_port_set && !server_port_set)
    option_error("You musy specify a port with option --listen-port or in the server name (--server server_name:port)");
  if (!server_name_set)
    g_mirror_mode = TRUE;
  if (g_mirror_mode && !listen_port_set)
    option_error("In mirror mode, you must specify a port with option --listen-port");
  listen_port = (listen_port_set ? listen_port : server_port);
  server_port = (server_port_set ? server_port : listen_port);
  check_bounds(server_port, TRUE, 1, FALSE, 0, "Illegal server port value");
  check_bounds(listen_port, TRUE, 1, FALSE, 0, "Illegal listen port value");
  check_bounds((int)bufsize, TRUE, 1, FALSE, 0, "Illegal buffer size value");
  check_bounds(connect_timeout, TRUE, 1, FALSE, 0, "Illegal timeout value");
  if (current_log_level < LL_ERROR)
    current_log_level = LL_ERROR;
  if (current_log_level > LL_DEBUG)
    current_log_level = LL_DEBUG;
}

int main(int argc, char *argv[]) {

  parse_options(argc, argv);
  telnet_str_bufsize = 2 * bufsize + 3;

  atexit(atexit_handler);
  signal(SIGTERM, sigterm_handler);
  signal(SIGABRT, sigabrt_handler);
  signal(SIGINT, sigint_handler);

  my_log_open();
  my_logs(LL_NORMAL, LP_DATETIME, PACKAGE_STRING " start");

    // Just to call WSAStartup, yes!
  os_init_network();
  
  memset(g_connection_socks,-1,sizeof(g_connection_socks));
  memset(g_session_socks,-1,sizeof(g_session_socks));

  almost_neverending_loop();

  if (quitting)
    return EXIT_FAILURE;
  quitting = TRUE;

  my_logs(LL_NORMAL, LP_DATETIME, PACKAGE_NAME " end");
  my_logs(LL_NORMAL, LP_NOTHING, "");
  my_log_close();

  return EXIT_SUCCESS;
}
