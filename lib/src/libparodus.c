/******************************************************************************
   Copyright [2016] [Comcast]

   Comcast Proprietary and Confidential

   All Rights Reserved.

   Unauthorized copying of this file, via any medium is strictly prohibited

******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>
#include <cimplog.h>
#include "libparodus.h"
#include "libparodus_time.h"
#include <pthread.h>
#include "libparodus_queues.h"

//#define PARODUS_SERVICE_REQUIRES_REGISTRATION 1

#define PARODUS_SERVICE_URL "tcp://127.0.0.1:6666"
//#define PARODUS_URL "ipc:///tmp/parodus_server.ipc"

#define PARODUS_CLIENT_URL "tcp://127.0.0.1:6667"
//#define CLIENT_URL "ipc:///tmp/parodus_client.ipc"

//const char *parodus_url = PARODUS_SERVICE_URL;
//const char *client_url = PARODUS_CLIENT_URL;

char parodus_url[32] = {'\0'};
char client_url[32] = {'\0'};


#define SOCK_SEND_TIMEOUT_MS 2000

#define MAX_RECONNECT_RETRY_DELAY_SECS 63

volatile int keep_alive_count = 0;
volatile int reconnect_count = 0;

#define END_MSG "---END-PARODUS---\n"
static const char *end_msg = END_MSG;

static char *closed_msg = "---CLOSED---\n";
static wrp_msg_t wrp_closed_msg;
static wrp_msg_t *closed_msg_ptr = &wrp_closed_msg;

typedef struct {
	bool receive;
	bool connect_on_every_send;
	int keepalive_timeout_secs;
} libpd_options_t;

static libpd_options_t libpd_options = {true, true, 0};

typedef struct {
	int len;
	char *msg;
} raw_msg_t;

static int rcv_sock = -1;
static int stop_rcv_sock = -1;
static int send_sock = -1;

#define WRP_QUEUE_SEND_TIMEOUT_MS	2000
#define WRP_QUEUE_NAME "/LIBPD_WRP_QUEUE"
#define WRP_QUEUE_SIZE 50

const char *wrp_queue_name = WRP_QUEUE_NAME;

static libpd_mq_t wrp_queue = NULL;

static pthread_t wrp_receiver_tid;
static pthread_mutex_t send_mutex=PTHREAD_MUTEX_INITIALIZER;

static const char *selected_service;

int flush_wrp_queue (uint32_t delay_ms);
static void make_closed_msg (wrp_msg_t *msg);
static int wrp_sock_send (wrp_msg_t *msg);
static void *wrp_receiver_thread (void *arg);
static void getParodusUrl();

#define RUN_STATE_RUNNING		1234
#define RUN_STATE_DONE			-1234

static volatile int run_state = 0;
static volatile bool auth_received = false;

//Call free in failure case for parodus_url and client_url
static void getParodusUrl()
{
	const char *parodusUrl = NULL;
	const char *clientUrl = NULL;
	const char * envParodus = getenv ("PARODUS_SERVICE_URL");
	const char * envClient = getenv ("PARODUS_CLIENT_URL");
  if( envParodus != NULL)
  {
    parodusUrl = envParodus;
  }
  else
  {
    parodusUrl = PARODUS_SERVICE_URL;
  }
  snprintf(parodus_url,sizeof(parodus_url),"%s", parodusUrl);
  cimplog_info("LIBPARODUS: ", "parodus url is  %s\n",parodus_url);
  
  if( envClient != NULL)
  {
    clientUrl = envClient;
  }
  else
  {
    clientUrl = PARODUS_CLIENT_URL;
  }
  snprintf(client_url,sizeof(client_url),"%s", clientUrl);
  cimplog_info("LIBPARODUS: ", "client url is  %s\n",client_url);
}

bool is_auth_received (void)
{
	return auth_received;
}

int connect_receiver (const char *rcv_url)
{
	int rcv_timeout;
	int sock;

	if (NULL == rcv_url) {
		return -1;
	}
  sock = nn_socket (AF_SP, NN_PULL);
	if (sock < 0) {
		cimplog_error("LIBPARODUS: ", "Unable to create rcv socket %s\n", rcv_url);
 		return -1;
	}
	if (libpd_options.keepalive_timeout_secs) { 
		rcv_timeout = libpd_options.keepalive_timeout_secs * 1000;
		if (nn_setsockopt (sock, NN_SOL_SOCKET, NN_RCVTIMEO, 
					&rcv_timeout, sizeof (rcv_timeout)) < 0) {
			cimplog_error("LIBPARODUS: ", "Unable to set socket timeout: %s\n", rcv_url);
 			return -1;
		}
	}
  if (nn_bind (sock, rcv_url) < 0) {
		cimplog_error("LIBPARODUS: ", "Unable to bind to receive socket %s\n", rcv_url);
		return -1;
	}
	return sock;
}

#define SHUTDOWN_SOCKET(sock) \
	if ((sock) != -1) \
		nn_shutdown ((sock), 0); \
	(sock) = 0;

void shutdown_socket (int *sock)
{
	if (*sock != -1) {
		nn_shutdown (*sock, 0);
		nn_close (*sock);
	}
	*sock = -1;
}

int connect_sender (const char *send_url)
{
	int sock;
	int send_timeout = SOCK_SEND_TIMEOUT_MS;

	if (NULL == send_url) {
		return -1;
	}
  sock = nn_socket (AF_SP, NN_PUSH);
	if (sock < 0) {
		cimplog_error("LIBPARODUS: ", "Unable to create send socket: %s\n", send_url);
 		return -1;
	}
	if (nn_setsockopt (sock, NN_SOL_SOCKET, NN_SNDTIMEO, 
				&send_timeout, sizeof (send_timeout)) < 0) {
		cimplog_error("LIBPARODUS: ", "Unable to set socket timeout: %s\n", send_url);
 		return -1;
	}
  if (nn_connect (sock, send_url) < 0) {
		cimplog_error("LIBPARODUS: ", "Unable to connect to send socket %s\n",
			send_url);
		return -1;
	}
	return sock;
}

static int create_thread (pthread_t *tid, void *(*thread_func) (void*))
{
	int rtn = pthread_create (tid, NULL, thread_func, NULL);
	if (rtn != 0)
		cimplog_error("LIBPARODUS: ", "Unable to create thread\n");
	return rtn; 
}

static bool is_closed_msg (wrp_msg_t *msg)
{
	return (msg->msg_type == WRP_MSG_TYPE__REQ) &&
		(strcmp (msg->u.req.dest, closed_msg) == 0);
}

static void wrp_free (void *msg)
{
	wrp_msg_t *wrp_msg;
	if (NULL == msg)
		return;
	wrp_msg = (wrp_msg_t *) msg;
	if (is_closed_msg (wrp_msg))
		return;
	wrp_free_struct (wrp_msg);
}

static int send_registration_msg (const char *service_name)
{
	wrp_msg_t reg_msg;
	reg_msg.msg_type = WRP_MSG_TYPE__SVC_REGISTRATION;
	reg_msg.u.reg.service_name = (char *) service_name;
	reg_msg.u.reg.url = client_url;
	return wrp_sock_send (&reg_msg);
}

static int parse_options (const char *option_str )
{
	int i;
	char c;
	bool entering_keepalive = false;
	unsigned keepalive_timeout = 0; 

	libpd_options.receive = true;
	libpd_options.connect_on_every_send = true;
	if (NULL == option_str)
		return 0;
	if (strcasecmp (option_str, "default") == 0)
		return 0;
	libpd_options.receive = false;
	libpd_options.connect_on_every_send = false;
	for (i=0; (c=option_str[i]) != 0; i++)
	{
		if (entering_keepalive) {
			if (c==',') {
				entering_keepalive = false;
				continue;
			}
			if ((c>='0') && (c<='9')) {
				keepalive_timeout = (10*keepalive_timeout) + c - '0';
				continue;
			}
			cimplog_error("LIBPARODUS: ", "Invalid keepalive value \'%c\'.\n", c);
			return -1;
		}
		if ((c==',') || (c==' '))
			continue;
		if (c=='R') {
			libpd_options.receive = true;
			continue;
		}
		if (c=='C') {
			libpd_options.connect_on_every_send = true;
			continue;
		}
		if (c=='K') {
			entering_keepalive = true;
			keepalive_timeout = 0;
			continue;
		}
		cimplog_error("LIBPARODUS: ", "Invalid option \'%c\'.\n", c);
		return -1;
	}
	libpd_options.keepalive_timeout_secs = keepalive_timeout;
	cimplog_debug("LIBPARODUS: ", "Options: Rcv: %d, Connect: %d\n",
		libpd_options.receive, libpd_options.connect_on_every_send);
	return 0;
}
 
int libparodus_init_ext (const char *service_name, const char *options)
{
	bool need_to_send_registration;
	int err;

	if (RUN_STATE_RUNNING == run_state) {
		return EALREADY;
	}
	if (0 != run_state) {
		return EBUSY;
	}
	if (parse_options (options) != 0) {
		return EINVAL;
	}
  //Call getParodusUrl to get parodus and client url
  getParodusUrl();
	make_closed_msg (&wrp_closed_msg);
	keep_alive_count = 0;
	reconnect_count = 0;
	auth_received = false;
	selected_service = service_name;
	if (libpd_options.receive) {
		cimplog_info("LIBPARODUS: ", "connecting receiver to %s\n", client_url);
		rcv_sock = connect_receiver (client_url);
		if (rcv_sock == -1) 
			return -1;
	}
	if (!libpd_options.connect_on_every_send) {
		cimplog_info("LIBPARODUS: ", "connecting sender to %s\n", parodus_url);
		send_sock = connect_sender (parodus_url);
		if (send_sock == -1) {
			shutdown_socket(&rcv_sock);
			return -1;
		}
	}
	if (libpd_options.receive) {
		// We use the stop_rcv_sock to send a stop msg to our own receive socket.
		stop_rcv_sock = connect_sender (client_url);
		if (stop_rcv_sock == -1) {
			shutdown_socket(&rcv_sock);
			shutdown_socket(&send_sock);
			return -1;
		}
		cimplog_info("LIBPARODUS: ", "Opened sockets\n");
		err = libpd_qcreate (&wrp_queue, wrp_queue_name, WRP_QUEUE_SIZE);
		if (err != 0) {
			shutdown_socket(&rcv_sock);
			shutdown_socket(&send_sock);
			shutdown_socket(&stop_rcv_sock);
			return -1;
		}
		cimplog_info("LIBPARODUS: ", "Created queues\n");
		if (create_thread (&wrp_receiver_tid, wrp_receiver_thread) != 0) {
			shutdown_socket(&rcv_sock);
			libpd_qdestroy (&wrp_queue, &wrp_free);
			shutdown_socket(&send_sock);
			shutdown_socket(&stop_rcv_sock);
			return -1;
		}
	}

	run_state = RUN_STATE_RUNNING;

#ifdef PARODUS_SERVICE_REQUIRES_REGISTRATION
	need_to_send_registration = true;
#else
	need_to_send_registration = libpd_options.receive;
#endif

	if (need_to_send_registration) {
		cimplog_info("LIBPARODUS: ", "sending registration msg\n");
		if (send_registration_msg (selected_service) != 0) {
			cimplog_error("LIBPARODUS: ", "error sending registration msg\n");
			libparodus_shutdown ();
			return -1;
		}
		cimplog_debug("LIBPARODUS: ", "Sent registration message\n");
	}
	return 0;
}

int libparodus_init (const char *service_name)
{
	return libparodus_init_ext (service_name, "R,C");
}

// When msg_len is given as -1, then msg is a null terminated string
static int sock_send (int sock, const char *msg, int msg_len)
{
  int bytes;
	if (msg_len < 0)
		msg_len = strlen (msg) + 1; // include terminating null
	bytes = nn_send (sock, msg, msg_len, 0);
  if (bytes < 0) { 
		cimplog_error("LIBPARODUS: ", "Error sending msg\n");
		return -1;
	}
  if (bytes != msg_len) {
		cimplog_error("LIBPARODUS: ", "Not all bytes sent, just %d\n", bytes);
		return -1;
	}
	return 0;
}

// returns 0 OK, 1 timedout, -1 error
static int sock_receive (raw_msg_t *msg)
{
	char *buf = NULL;
  msg->len = nn_recv (rcv_sock, &buf, NN_MSG, 0);

  if (msg->len < 0) {
		cimplog_error("LIBPARODUS: ", "Error receiving msg\n");
		if (errno == ETIMEDOUT)
			return 1; 
		return -1;
	}
	msg->msg = buf;
	return 0;
}

int libparodus_shutdown (void)
{
	int rtn;

	if (RUN_STATE_RUNNING != run_state) {
		return -1;
	}

	run_state = RUN_STATE_DONE;
	cimplog_info("LIBPARODUS: ", "Shutting Down\n");
	if (libpd_options.receive) {
		sock_send (stop_rcv_sock, end_msg, -1);
	 	rtn = pthread_join (wrp_receiver_tid, NULL);
		if (rtn != 0)
			cimplog_error("LIBPARODUS: ", "Error terminating wrp receiver thread\n");
		shutdown_socket(&rcv_sock);
		cimplog_info("LIBPARODUS: ", "Flushing wrp queue\n");
		flush_wrp_queue (5);
		libpd_qdestroy (&wrp_queue, &wrp_free);
	}
	shutdown_socket(&send_sock);
	if (libpd_options.receive) {
		shutdown_socket(&stop_rcv_sock);
	}
	run_state = 0;
	auth_received = false;
	return 0;
}

// returns 0 OK
//  1 timed out
// -1 mq_receive error
static int timed_wrp_queue_receive (wrp_msg_t **msg, unsigned timeout_ms)
{
	int rtn;
	void *raw_msg;

	rtn = libpd_qreceive (wrp_queue, &raw_msg, timeout_ms);
	if (rtn == ETIMEDOUT)
		return 1;
	if (rtn != 0) {
		cimplog_error("LIBPARODUS: ", "Unable to receive on queue /WRP_QUEUE\n");
		return -1;
	}
	*msg = (wrp_msg_t *) raw_msg;
	cimplog_debug("LIBPARODUS: ", "receive msg on WRP QUEUE\n");
	return 0;
}

static void make_closed_msg (wrp_msg_t *msg)
{
	msg->msg_type = WRP_MSG_TYPE__REQ;
	msg->u.req.transaction_uuid = closed_msg;
	msg->u.req.source = closed_msg;
	msg->u.req.dest = closed_msg;
	msg->u.req.payload = (void*) closed_msg;
	msg->u.req.payload_size = strlen(closed_msg);
}

// returns 0 OK
//  2 closed msg received
//  1 timed out
// -1 mq_receive error
// -3 no receive option
int libparodus_receive__ (wrp_msg_t **msg, uint32_t ms)
{
	int err;

	if (!libpd_options.receive) {
		cimplog_error("LIBPARODUS: ", "No receive option on libparodus_receive\n");
		return -3;
	}

	err = timed_wrp_queue_receive (msg, ms);
	if (err != 0)
		return err;
	if (*msg == NULL) {
		cimplog_debug("LIBPARODUS: ", "NULL msg from wrp queue\n");
		return -1;
	}
	cimplog_debug("LIBPARODUS: ", "received msg type %d\n", (*msg)->msg_type);
	if (is_closed_msg (*msg)) {
		cimplog_info("LIBPARODUS: ", "closed msg received\n");
		return 2;
	}
	return 0;
}

// returns 0 OK
//  2 closed msg received
//  1 timed out
// -1 mq_receive error
int libparodus_receive (wrp_msg_t **msg, uint32_t ms)
{
	if (RUN_STATE_RUNNING != run_state) {
		return -1;
	}
	return libparodus_receive__ (msg, ms);
}

int libparodus_close_receiver__ (void)
{
	if (!libpd_options.receive) {
		cimplog_error("LIBPARODUS: ", "No receive option on libparodus_close_receiver\n");
		return -3;
	}
	if (libpd_qsend (wrp_queue, (void *) closed_msg_ptr, 
				WRP_QUEUE_SEND_TIMEOUT_MS) != 0)
		return -1;
	cimplog_info("LIBPARODUS: ", "Sent closed msg\n");
	return 0;
}

int libparodus_close_receiver (void)
{
	if (RUN_STATE_RUNNING != run_state) {
		return -1;
	}
	return libparodus_close_receiver__ ();
}

static int wrp_sock_send (wrp_msg_t *msg)
{
	int rtn;
	ssize_t msg_len;
	void *msg_bytes;

	pthread_mutex_lock (&send_mutex);
	msg_len = wrp_struct_to (msg, WRP_BYTES, &msg_bytes);
	if (msg_len < 1) {
		cimplog_error("LIBPARODUS: ", "error converting WRP to bytes\n");
		pthread_mutex_unlock (&send_mutex);
		return -1;
	}

	if (libpd_options.connect_on_every_send) {
		send_sock = connect_sender (parodus_url);
		if (send_sock == -1) {
			free (msg_bytes);
			pthread_mutex_unlock (&send_mutex);
			return -1;
		}
	}

	rtn = sock_send (send_sock, (const char *)msg_bytes, msg_len);

	if (libpd_options.connect_on_every_send) {
		shutdown_socket (&send_sock);
	}

	free (msg_bytes);
	pthread_mutex_unlock (&send_mutex);
	return rtn;
}

int libparodus_send__ (wrp_msg_t *msg)
{
	if (libpd_options.receive && (!auth_received)) {
		return -1;
	}

	return wrp_sock_send (msg);
}

int libparodus_send (wrp_msg_t *msg)
{
	if (RUN_STATE_RUNNING != run_state) {
		return -1;
	}
	return libparodus_send__ (msg);
}


static char *find_wrp_msg_dest (wrp_msg_t *wrp_msg)
{
	if (wrp_msg->msg_type == WRP_MSG_TYPE__REQ)
		return wrp_msg->u.req.dest;
	if (wrp_msg->msg_type == WRP_MSG_TYPE__EVENT)
		return wrp_msg->u.event.dest;
	if (wrp_msg->msg_type == WRP_MSG_TYPE__CREATE)
		return wrp_msg->u.crud.dest;
	if (wrp_msg->msg_type == WRP_MSG_TYPE__RETREIVE)
		return wrp_msg->u.crud.dest;
	if (wrp_msg->msg_type == WRP_MSG_TYPE__UPDATE)
		return wrp_msg->u.crud.dest;
	if (wrp_msg->msg_type == WRP_MSG_TYPE__DELETE)
		return wrp_msg->u.crud.dest;
	return NULL;
}

static void wrp_receiver_reconnect (void)
{
	int p = 2;
	int retry_delay = 0;

	while (true)
	{
		shutdown_socket (&rcv_sock);
		if (retry_delay < MAX_RECONNECT_RETRY_DELAY_SECS) {
			p = p+p;
			retry_delay = p-1;
		}
		sleep (retry_delay);
		cimplog_debug("LIBPARODUS: ", "Retrying receiver connection\n");
		rcv_sock = connect_receiver (client_url);
		if (rcv_sock != -1) {
			reconnect_count++;
			return;
		}
	}
}

static void *wrp_receiver_thread (void *arg __attribute__ ((unused)) )
{
	int rtn, msg_len;
	raw_msg_t raw_msg;
	wrp_msg_t *wrp_msg;
	int end_msg_len = strlen(end_msg);
	char *msg_dest, *msg_service;

	cimplog_info("LIBPARODUS: ", "Starting wrp receiver thread\n");
	while (1) {
		rtn = sock_receive (&raw_msg);
		if (rtn != 0) {
			if (rtn == 1) { // timed out
				wrp_receiver_reconnect ();
				continue;
			}
			break;
		}
		if (raw_msg.len >= end_msg_len) {
			if (strncmp (raw_msg.msg, end_msg, end_msg_len) == 0) {
				nn_freemsg (raw_msg.msg);
				break;
			}
		}
		if (RUN_STATE_RUNNING != run_state) {
			nn_freemsg (raw_msg.msg);
			continue;
		}
		cimplog_debug("LIBPARODUS: ", "Converting bytes to WRP\n"); 
 		msg_len = (int) wrp_to_struct (raw_msg.msg, raw_msg.len, WRP_BYTES, &wrp_msg);
		nn_freemsg (raw_msg.msg);
		if (msg_len < 1) {
			cimplog_error("LIBPARODUS: ", "error converting bytes to WRP\n");
			continue;
		}
		if (wrp_msg->msg_type == WRP_MSG_TYPE__AUTH) {
			if (auth_received)
				cimplog_error("LIBPARODUS: ", "extra AUTH msg received\n");
			else
				cimplog_info("LIBPARODUS: ", "AUTH msg received\n");
			auth_received = true;
			wrp_free_struct (wrp_msg);
			continue;
		}
		if (!auth_received) {
			cimplog_error("LIBPARODUS: ", "LIBPARADOS: AUTH msg not received\n");
			wrp_free_struct (wrp_msg);
			continue;
		}

		if (wrp_msg->msg_type == WRP_MSG_TYPE__SVC_ALIVE) {
			cimplog_debug("LIBPARODUS: ", "received keep alive message\n");
			keep_alive_count++;
			wrp_free_struct (wrp_msg);
			continue;
		}

		// Pass thru REQ, EVENT, and CRUD if dest matches the selected service
		msg_dest = find_wrp_msg_dest (wrp_msg);
		if (NULL == msg_dest) {
			cimplog_error("LIBPARODUS: ", "LIBPARADOS: Unprocessed msg type %d received\n",
				wrp_msg->msg_type);
			wrp_free_struct (wrp_msg);
			continue;
		}
		msg_service = strrchr (msg_dest, '/');
		if (NULL == msg_service) {
			wrp_free_struct (wrp_msg);
			continue;
		}
		msg_service++;
		if (strcmp (msg_service, selected_service) != 0) {
			wrp_free_struct (wrp_msg);
			continue;
		}
		cimplog_debug("LIBPARODUS: ", "received msg directed to service %s\n",
			selected_service);
		libpd_qsend (wrp_queue, (void *) wrp_msg, WRP_QUEUE_SEND_TIMEOUT_MS);
	}
	cimplog_info("LIBPARODUS: ", "Ended wrp receiver thread\n");
	return NULL;
}


int flush_wrp_queue (uint32_t delay_ms)
{
	wrp_msg_t *wrp_msg;
	int count = 0;
	int err;

	while (1) {
		err = timed_wrp_queue_receive (&wrp_msg, delay_ms);
		if (err == 1)	// timed out
			break;
		if (err != 0)
			return -1;
		count++;
		wrp_free (wrp_msg);
	}
	cimplog_info("LIBPARODUS: ", "flushed %d messages out of WRP Queue\n", 
		count);
	return count;
}

// Functions used by libpd_test.c

int test_create_wrp_queue (void)
{
	return libpd_qcreate (&wrp_queue, wrp_queue_name, 24);
}

void test_close_wrp_queue (void)
{
	libpd_qdestroy (&wrp_queue, &wrp_free);
}

void test_send_wrp_queue_ok (void)
{
	wrp_msg_t *reg_msg = (wrp_msg_t *) malloc (sizeof(wrp_msg_t));
	char *name;
	reg_msg->msg_type = WRP_MSG_TYPE__SVC_REGISTRATION;
	name = (char*) malloc (4);
	strcpy (name, "iot");
	reg_msg->u.reg.service_name = name;
	name = (char *) malloc (strlen(PARODUS_CLIENT_URL) + 1);
	strcpy (name, PARODUS_CLIENT_URL);
	reg_msg->u.reg.url = name;
	libpd_qsend (wrp_queue, (void *) reg_msg, WRP_QUEUE_SEND_TIMEOUT_MS);
}

int test_close_receiver (void)
{
	make_closed_msg (&wrp_closed_msg);
	return libparodus_close_receiver__ ();
}



