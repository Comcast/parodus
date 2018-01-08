/**
 * Copyright 2015 Comcast Cable Communications Management, LLC
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
/**
 * @file config.h
 *
 * @description This file contains configuration details of parodus
 *
 */

#include <stdio.h>
#include <fcntl.h> 
#include "config.h"
#include "ParodusInternal.h"

#define MAX_BUF_SIZE            128
/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/

static ParodusCfg parodusCfg;
static char token_application[64] = {'\0'};

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

ParodusCfg *get_parodus_cfg(void) 
{
    return &parodusCfg;
}

void set_parodus_cfg(ParodusCfg *cfg) 
{
    memcpy(&parodusCfg, cfg, sizeof(ParodusCfg));
}

char *get_token_application(void)
{
    return token_application;
}

// the algorithm mask indicates which algorithms are allowed
#if 0
unsigned int get_algo_mask (const char *algo_str)
{
  unsigned int mask = 0;
  char *tok;
	int alg_val;
#define BUFLEN 128
	char algo_buf[BUFLEN];

	strncpy (algo_buf, algo_str, BUFLEN-1);
	algo_buf[BUFLEN-1] = 0;

	tok = strtok(algo_buf, ":");
	while(tok!=NULL)
	{
		alg_val = cjwt_alg_str_to_enum (tok);
		if ((alg_val < 0)  || (alg_val >= num_algorithms)) {
       ParodusError("Invalid jwt algorithm %s\n", tok);
       abort ();
		}
		mask |= (1<<alg_val);
		tok = strtok(NULL,":");
	}
	return mask;
#undef BUFLEN
}
#endif

static int open_input_file (const char *fname)
{
  int fd = open(fname, O_RDONLY);
  if (fd<0)
  {
    ParodusError ("File %s open error\n", fname);
    abort ();
  }
  return fd;
} 

void read_key_from_file (const char *fname, char *buf, size_t buflen)
{
  ssize_t nbytes;
  int fd = open_input_file(fname);
  nbytes = read(fd, buf, buflen);
  if (nbytes < 0)
  {
    ParodusError ("Read file %s error\n", fname);
    close(fd);
    abort ();
  }
  close(fd);
  ParodusInfo ("%d bytes read\n", nbytes);
}

void get_webpa_token(char *token, char *name, size_t len, char *serNum, char *mac)
{
    FILE* out = NULL, *file = NULL;
    char command[MAX_BUF_SIZE] = {'\0'};
    if(strlen(name)>0)
    {
        file = fopen(name, "r");
        if(file)
        {
            snprintf(command,sizeof(command),"%s %s %s",name,serNum,mac);
            out = popen(command, "r");
            if(out)
            {
                fgets(token, len, out);
                pclose(out);
            }
            fclose(file);
        }
        else
        {
            ParodusError ("File %s open error\n", name);
        }
    }
}

// strips ':' characters
// verifies that there exactly 12 characters
static int parse_mac_address (char *target, const char *arg)
{
	int count = 0;
	int i;
	char c;

	for (i=0; (c=arg[i]) != 0; i++) {
		if (c !=':')
			count++;
	}
	if (count != 12)
		return -1;			// bad mac address
	for (i=0; (c=arg[i]) != 0; i++) {
		if (c != ':')
			*(target++) = c;
	}
	*target = 0;	// terminating null
	return 0;
}

void parseCommandLine(int argc,char **argv,ParodusCfg * cfg)
{
    static const struct option long_options[] = {
        {"hw-model",                required_argument, 0, 'm'},
        {"hw-serial-number",        required_argument, 0, 's'},
        {"hw-manufacturer",         required_argument, 0, 'f'},
        {"hw-mac",                  required_argument, 0, 'd'},
        {"hw-last-reboot-reason",   required_argument, 0, 'r'},
        {"fw-name",                 required_argument, 0, 'n'},
        {"boot-time",               required_argument, 0, 'b'},
        {"webpa-url",               required_argument, 0, 'u'},
        {"webpa-ping-timeout",      required_argument, 0, 't'},
        {"webpa-backoff-max",       required_argument, 0, 'o'},
        {"webpa-interface-used",    required_argument, 0, 'i'},
        {"parodus-local-url",       required_argument, 0, 'l'},
        {"partner-id",              required_argument, 0, 'p'},
#ifdef ENABLE_SESHAT
        {"seshat-url",              required_argument, 0, 'e'},
#endif
#ifdef ENABLE_CJWT
        {"dns-id",                  required_argument, 0, 'D'},
        {"jwt-algo",                required_argument, 0, 'a'},
        {"jwt-key",                 required_argument, 0, 'k'},
#endif
        {"ssl-cert-path",           required_argument, 0, 'c'},
        {"force-ipv4",              no_argument,       0, '4'},
        {"force-ipv6",              no_argument,       0, '6'},
        {"webpa-token",             required_argument, 0, 'T'},
        {"secure-flag",             required_argument, 0, 'F'},
        {"port",                    required_argument, 0, 'P'},
        {0, 0, 0, 0}
    };
    int c;
    ParodusInfo("Parsing parodus command line arguments..\n");

    if (cfg == NULL)
	return;

    while (1)
    {

      /* getopt_long stores the option index here. */
      int option_index = 0;
      c = getopt_long (argc, argv, "m:s:f:d:r:n:b:u:t:o:i:l:p:e:D:a:k:c:4:6:T:F:P",
				long_options, &option_index);

      /* Detect the end of the options. */
      if (c == -1)
        break;

      switch (c)
        {
        case 'm':
          parStrncpy(cfg->hw_model, optarg,sizeof(cfg->hw_model));
          ParodusInfo("hw-model is %s\n",cfg->hw_model);
         break;
        
        case 's':
          parStrncpy(cfg->hw_serial_number,optarg,sizeof(cfg->hw_serial_number));
          ParodusInfo("hw_serial_number is %s\n",cfg->hw_serial_number);
          break;

        case 'f':
          parStrncpy(cfg->hw_manufacturer, optarg,sizeof(cfg->hw_manufacturer));
          ParodusInfo("hw_manufacturer is %s\n",cfg->hw_manufacturer);
          break;

        case 'd':
					if (parse_mac_address (cfg->hw_mac, optarg) == 0) {
            ParodusInfo ("hw_mac is %s\n",cfg->hw_mac);
					} else {
						ParodusError ("Bad mac address %s\n", optarg);
						abort ();
					}
          break;
#ifdef ENABLE_SESHAT
         case 'e':
           parStrncpy(cfg->seshat_url, optarg,sizeof(cfg->seshat_url));
           ParodusInfo("seshat_url is %s\n",cfg->seshat_url);
          break;
#endif
        case 'r':
          parStrncpy(cfg->hw_last_reboot_reason, optarg,sizeof(cfg->hw_last_reboot_reason));
          ParodusInfo("hw_last_reboot_reason is %s\n",cfg->hw_last_reboot_reason);
          break;

        case 'n':
          parStrncpy(cfg->fw_name, optarg,sizeof(cfg->fw_name));
          ParodusInfo("fw_name is %s\n",cfg->fw_name);
          break;

        case 'b':
          cfg->boot_time = atoi(optarg);
          ParodusInfo("boot_time is %d\n",cfg->boot_time);
          break;
       
         case 'u':
          parStrncpy(cfg->webpa_url, optarg,sizeof(cfg->webpa_url));
          ParodusInfo("webpa_url is %s\n",cfg->webpa_url);
          break;
        
        case 't':
          cfg->webpa_ping_timeout = atoi(optarg);
          ParodusInfo("webpa_ping_timeout is %d\n",cfg->webpa_ping_timeout);
          break;

        case 'o':
          cfg->webpa_backoff_max = atoi(optarg);
          ParodusInfo("webpa_backoff_max is %d\n",cfg->webpa_backoff_max);
          break;

        case 'i':
          parStrncpy(cfg->webpa_interface_used, optarg,sizeof(cfg->webpa_interface_used));
          ParodusInfo("webpa_interface_used is %s\n",cfg->webpa_interface_used);
          break;
          
        case 'l':
          parStrncpy(cfg->local_url, optarg,sizeof(cfg->local_url));
          ParodusInfo("parodus local_url is %s\n",cfg->local_url);
          break;
#ifdef ENABLE_CJWT
        case 'D':
          // like 'fabric' or 'test'
          // this parameter is used, along with the hw_mac parameter
          // to create the dns txt record id
          parStrncpy(cfg->dns_id, optarg,sizeof(cfg->dns_id));
          ParodusInfo("parodus dns_id is %s\n",cfg->dns_id);
          break;
		 
	case 'a':
          parStrncpy(cfg->jwt_algo, optarg, sizeof(cfg->jwt_algo));
          ParodusInfo("jwt_algo is %s\n",cfg->jwt_algo);
          break;
	case 'k':
          // if the key argument has a '.' character in it, then it is
          // assumed to be a file, and the file is read in.
          if (strchr (optarg, '.') == NULL) {
             parStrncpy(cfg->jwt_key, optarg,sizeof(cfg->jwt_key));
          } else {
             read_key_from_file (optarg, cfg->jwt_key, sizeof(cfg->jwt_key));
          }
          ParodusInfo("jwt_key is %s\n",cfg->jwt_key);
          break;
#endif
        case 'p':
          parStrncpy(cfg->partner_id, optarg,sizeof(cfg->partner_id));
          ParodusInfo("partner_id is %s\n",cfg->partner_id);
          break;

        case 'c':
          parStrncpy(cfg->cert_path, optarg,sizeof(cfg->cert_path));
          ParodusInfo("cert_path is %s\n",cfg->cert_path);
          break;

        case '4':
          ParodusInfo("Force IPv4\n");
          cfg->flags |= FLAGS_IPV4_ONLY;
          break;

        case '6':
          ParodusInfo("Force IPv6\n");
          cfg->flags |= FLAGS_IPV6_ONLY;
          break;

        case 'T':
          parStrncpy(token_application, optarg, sizeof(token_application));
	  get_webpa_token(cfg->webpa_token,optarg,sizeof(cfg->webpa_token),cfg->hw_serial_number,cfg->hw_mac);
          ParodusInfo("webpa_token is %s\n",cfg->webpa_token);
          break;

        case 'F':
          if(strcmp(optarg,"http") == 0)
          {
            cfg->secure_flag = 0;
          }
          else if(strcmp(optarg,"https") == 0)
          {
            cfg->secure_flag = FLAGS_SECURE;
          }
          else
          {
            ParodusError("Invalid secure flag. Valid values are 'http' and 'https', using default 'https'\n");
          }
          ParodusInfo("cfg->secure_flag is %d\n",cfg->secure_flag);
    	  ParodusInfo("cfg->port is %d\n",cfg->port);
          break;

        case 'P':
          cfg->port = atoi(optarg);
          break;

        case '?':
          /* getopt_long already printed an error message. */
          break;

        default:
           ParodusError("Enter Valid commands..\n");
          abort ();
        }
    }

    ParodusPrint("argc is :%d\n", argc);
    ParodusPrint("optind is :%d\n", optind);

    /* Print any remaining command line arguments (not options). */
    if (optind < argc)
    {
      ParodusPrint ("non-option ARGV-elements: ");
      while (optind < argc)
        ParodusPrint ("%s ", argv[optind++]);
      putchar ('\n');
    }
}

void setDefaultValuesToCfg(ParodusCfg *cfg)
{
    if(cfg == NULL)
    {
        ParodusError("cfg is NULL\n");
        return;
    }
    
    ParodusInfo("Setting default values to parodusCfg\n");
    parStrncpy(cfg->local_url, PARODUS_UPSTREAM, sizeof(cfg->local_url));

#ifdef ENABLE_CJWT
   
    parStrncpy(cfg->dns_id, DNS_ID,sizeof(cfg->dns_id));

    parStrncpy(cfg->jwt_key, "\0", sizeof(cfg->jwt_key));
    
    parStrncpy(cfg->jwt_algo, "\0", sizeof(cfg->jwt_algo));
#endif
   
    parStrncpy(cfg->cert_path, "\0", sizeof(cfg->cert_path));

    cfg->flags |= FLAGS_SECURE;
    cfg->secure_flag = FLAGS_SECURE;
    cfg->port = 8080;
    
    parStrncpy(cfg->webpa_path_url, WEBPA_PATH_URL,sizeof(cfg->webpa_path_url));
    
    snprintf(cfg->webpa_protocol, sizeof(cfg->webpa_protocol), "%s-%s", PROTOCOL_VALUE, GIT_COMMIT_TAG);
    ParodusInfo(" cfg->webpa_protocol is %s\n", cfg->webpa_protocol);
    
    parStrncpy(cfg->webpa_uuid, "1234567-345456546",sizeof(cfg->webpa_uuid));
    ParodusPrint("cfg->webpa_uuid is :%s\n", cfg->webpa_uuid);
    
}

void loadParodusCfg(ParodusCfg * config,ParodusCfg *cfg)
{
    if(config == NULL)
    {
        ParodusError("config is NULL\n");
        return;
    }
    
    if(strlen (config->hw_model) !=0)
    {
          parStrncpy(cfg->hw_model, config->hw_model, sizeof(cfg->hw_model));
    }
    else
    {
        ParodusPrint("hw_model is NULL. read from tmp file\n");
    }
    if( strlen(config->hw_serial_number) !=0)
    {
        parStrncpy(cfg->hw_serial_number, config->hw_serial_number, sizeof(cfg->hw_serial_number));
    }
    else
    {
        ParodusPrint("hw_serial_number is NULL. read from tmp file\n");
    }
    if(strlen(config->hw_manufacturer) !=0)
    {
        parStrncpy(cfg->hw_manufacturer, config->hw_manufacturer,sizeof(cfg->hw_manufacturer));
    }
    else
    {
        ParodusPrint("hw_manufacturer is NULL. read from tmp file\n");
    }
    if(strlen(config->hw_mac) !=0)
    {
       parStrncpy(cfg->hw_mac, config->hw_mac,sizeof(cfg->hw_mac));
    }
    else
    {
        ParodusPrint("hw_mac is NULL. read from tmp file\n");
    }
    if(strlen (config->hw_last_reboot_reason) !=0)
    {
         parStrncpy(cfg->hw_last_reboot_reason, config->hw_last_reboot_reason,sizeof(cfg->hw_last_reboot_reason));
    }
    else
    {
        ParodusPrint("hw_last_reboot_reason is NULL. read from tmp file\n");
    }
    if(strlen(config->fw_name) !=0)
    {   
        parStrncpy(cfg->fw_name, config->fw_name,sizeof(cfg->fw_name));
    }
    else
    {
        ParodusPrint("fw_name is NULL. read from tmp file\n");
    }
    if( strlen(config->webpa_url) !=0)
    {
        parStrncpy(cfg->webpa_url, config->webpa_url,sizeof(cfg->webpa_url));
    }
    else
    {
        ParodusPrint("webpa_url is NULL. read from tmp file\n");
    }
    if(strlen(config->webpa_interface_used )!=0)
    {
        parStrncpy(cfg->webpa_interface_used, config->webpa_interface_used,sizeof(cfg->webpa_interface_used));
    }
    else
    {
        ParodusPrint("webpa_interface_used is NULL. read from tmp file\n");
    }
    if( strlen(config->local_url) !=0)
    {
        parStrncpy(cfg->local_url, config->local_url,sizeof(cfg->local_url));
    }
    else
    {
		ParodusInfo("parodus local_url is NULL. adding default url\n");
		parStrncpy(cfg->local_url, PARODUS_UPSTREAM, sizeof(cfg->local_url));
        
    }

    if( strlen(config->partner_id) !=0)
    {
        parStrncpy(cfg->partner_id, config->partner_id,sizeof(cfg->partner_id));
    }
    else
    {
		ParodusPrint("partner_id is NULL. read from tmp file\n");
    }
#ifdef ENABLE_SESHAT
    if( strlen(config->seshat_url) !=0)
    {
        parStrncpy(cfg->seshat_url, config->seshat_url,sizeof(cfg->seshat_url));
    }
    else
    {
        ParodusInfo("seshat_url is NULL. Read from tmp file\n");
    }
#endif
#ifdef ENABLE_CJWT
     if( strlen(config->dns_id) !=0)
    {
        parStrncpy(cfg->dns_id, config->dns_id,sizeof(cfg->dns_id));
    }
    else
    {
	ParodusInfo("parodus dns-id is NULL. adding default\n");
	parStrncpy(cfg->dns_id, DNS_ID,sizeof(cfg->dns_id));
    }

    if(strlen(config->jwt_key )!=0)
    {
        parStrncpy(cfg->jwt_key, config->jwt_key,sizeof(cfg->jwt_key));
    }
    else
    {
        parStrncpy(cfg->jwt_key, "\0", sizeof(cfg->jwt_key));
        ParodusPrint("jwt_key is NULL. set to empty\n");
    }
    
    if(strlen(config->jwt_algo )!=0)
    {
        parStrncpy(cfg->jwt_algo, config->jwt_algo,sizeof(cfg->jwt_algo));
    }
    else
    {
        parStrncpy(cfg->jwt_algo, "\0", sizeof(cfg->jwt_algo));
        ParodusPrint("jwt_algo is NULL. set to empty\n");
    }
#endif
    if(strlen(config->cert_path )!=0)
    {
        parStrncpy(cfg->cert_path, config->cert_path,sizeof(cfg->cert_path));
    }
    else
    {
        parStrncpy(cfg->cert_path, "\0", sizeof(cfg->cert_path));
        ParodusPrint("cert_path is NULL. set to empty\n");
    }

    if( strlen(config->webpa_token) !=0)
    {
        parStrncpy(cfg->webpa_token, config->webpa_token,sizeof(cfg->webpa_token));
    }
    else
    {
        ParodusPrint("webpa_token is NULL. read from tmp file\n");
    }

    cfg->boot_time = config->boot_time;
    cfg->flags |= FLAGS_SECURE;
    cfg->webpa_ping_timeout = config->webpa_ping_timeout;
    cfg->webpa_backoff_max = config->webpa_backoff_max;
    
    cfg->secure_flag = config->secure_flag;
    ParodusPrint("cfg->secure_flag is :%d\n",cfg->secure_flag);
    
    cfg->port = config->port;
    ParodusPrint("cfg->port is :%d\n",cfg->port);
    parStrncpy(cfg->webpa_path_url, WEBPA_PATH_URL,sizeof(cfg->webpa_path_url));
    snprintf(cfg->webpa_protocol, sizeof(cfg->webpa_protocol), "%s-%s", PROTOCOL_VALUE, GIT_COMMIT_TAG);
    ParodusInfo("cfg->webpa_protocol is %s\n", cfg->webpa_protocol);
    parStrncpy(cfg->webpa_uuid, "1234567-345456546",sizeof(cfg->webpa_uuid));
    ParodusPrint("cfg->webpa_uuid is :%s\n", cfg->webpa_uuid);
    
}


