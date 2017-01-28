/**
 * Copyright 2016 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#ifndef  _LIBPARODUS_H
#define  _LIBPARODUS_H

#include <wrp-c/wrp-c.h>

/**
 * This module is linked with the client, and provides connectivity
 * to the parodus service.
 */ 


/**
 * Initialize the parodus wrp interface
 *
 * @param service_name the service name registered for
 * @return 0 on success, valid errno otherwise.
 * @note this is the same as libparodus_init_ext (service_name, "R,C");
 */
int libparodus_init (const char *service_name);

/**
 * Initialize the parodus wrp interface
 *
 * @param service_name the service name registered for
 * @param options option string, 
 * 		currently 'R' for receiver, 'C' for connect-on-every-send
 * @return 0 on success, valid errno otherwise.
 */
int libparodus_init_ext (const char *service_name, const char *options);

/**
 *  Receives the next message in the queue that was sent to this service, waiting
 *  the prescribed number of milliseconds before returning.
 *
 *  @note msg will be set to NULL if no message is present during the time
 *  allotted.
 *
 *  @param msg the pointer to receive the next msg struct
 *  @param ms the number of milliseconds to wait for the next message
 *
 *  @return 0 on success, 2 if closed msg received, 1 if timed out, 
 *   -1 if receive error, -3 no receiver option
 *
 *  @note don't free the msg when return is 2. 
 */
int libparodus_receive (wrp_msg_t **msg, uint32_t ms);

/**
 * Sends a close message to the receiver
 *
 */
int libparodus_close_receiver (void);

/**
 * Shut down the parodus wrp interface
 *
*/
int libparodus_shutdown (void);


/**
 * Send a wrp message to the parodus service
 *
 * @param msg wrp message to send
 *
 * @return 0 on success, -1 otherwise.
 */
int libparodus_send (wrp_msg_t *msg);


#endif
