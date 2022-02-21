#include <stdarg.h>
#include <stdio.h>

#include "scap_event_helpers.h"
#include "../../../driver/ppm_events_public.h"

extern const struct ppm_event_info g_event_info[PPM_EVENT_MAX];

inline size_t scap_event_ensure_size(scap_evt **pevent, size_t cur_size, size_t desired_size)
{
	if(cur_size >= desired_size)
	{
		return cur_size;
	}

	if(cur_size == 0)
	{
		// compute next higher power of 2 of the the initial size
		desired_size--;
		desired_size |= desired_size >> 1;
		desired_size |= desired_size >> 2;
		desired_size |= desired_size >> 4;
		desired_size |= desired_size >> 8;
		desired_size |= desired_size >> 16;
		desired_size++;

		*pevent = malloc(desired_size);
		if(*pevent == NULL)
		{
			return 0;
		}

		return desired_size;
	}

	size_t next_size = cur_size * 2;
	*pevent = realloc(*pevent, next_size);
	if(*pevent == NULL)
	{
		return 0;
	}

	return next_size;
}

inline uint16_t *scap_syscall_event_param_lengths(scap_evt *event)
{
	return (uint16_t *)((char *)event + sizeof(struct ppm_evt_hdr));
}

size_t scap_event_create_v(scap_evt **pevent, size_t bufsize, enum ppm_event_type event_type, ...)
{
	va_list ap;

	const struct ppm_event_info *event_info = &g_event_info[event_type];
	size_t len = sizeof(struct ppm_evt_hdr) + sizeof(uint16_t) * event_info->nparams;
	bufsize = scap_event_ensure_size(pevent, bufsize, len);
	memset(*pevent, 0, len);
    (*pevent)->type = event_type;
    (*pevent)->nparams = event_info->nparams;

	va_start(ap, event_type);
	for(int i = 0; i < event_info->nparams; i++)
	{
		const struct ppm_param_info *pi = &event_info->params[i];
		void *param_buf = NULL;
		size_t param_size = 0;

        uint8_t u8_arg;
        uint16_t u16_arg;
        uint32_t u32_arg;
        uint64_t u64_arg;

		switch(pi->type)
		{
		case PT_INT8:
		case PT_UINT8:
		case PT_FLAGS8:	    /* this is an UINT8, but will be interpreted as 8 bit flags. */
		case PT_SIGTYPE:    /* An 8bit signal number */
		case PT_L4PROTO:    /* A 1 byte IP protocol type. */
		case PT_SOCKFAMILY: /* A 1 byte socket family. */
			u8_arg = (uint8_t) (va_arg(ap, int) & 0xff);
			param_buf = &u8_arg;
			param_size = 1;
			break;

		case PT_INT16:
		case PT_UINT16:
		case PT_SYSCALLID: /* A 16bit system call ID. Can be used as a key for the g_syscall_info_table table. */
		case PT_PORT:	   /* A TCP/UDP prt. 2 bytes. */
		case PT_FLAGS16:   /* this is an UINT16, but will be interpreted as 16 bit flags. */
			u16_arg = (uint16_t) (va_arg(ap, int) & 0xffff);
			param_buf = &u16_arg;
			param_size = 2;
			break;

		case PT_INT32:
		case PT_UINT32:
		case PT_BOOL:	  /* A boolean value, 4 bytes. */
		case PT_IPV4ADDR: /* A 4 byte raw IPv4 address. */
		case PT_UID:	  /* this is an UINT32, MAX_UINT32 will be interpreted as no value. */
		case PT_GID:	  /* this is an UINT32, MAX_UINT32 will be interpreted as no value. */
		case PT_FLAGS32:  /* this is an UINT32, but will be interpreted as 32 bit flags. */
		case PT_SIGSET:	  /* sigset_t. I only store the lower UINT32 of it */
		case PT_MODE:	  /* a 32 bit bitmask to represent file modes. */
            u32_arg = va_arg(ap, uint32_t);
            param_buf = &u32_arg;
            param_size = 4;
			break;

		case PT_INT64:
		case PT_UINT64:
		case PT_ERRNO:	 /* this is an INT64, but will be interpreted as an error code */
		case PT_FD:	 /* An fd, 64bit */
		case PT_PID:	 /* A pid/tid, 64bit */
		case PT_RELTIME: /* A relative time. Seconds * 10^9  + nanoseconds. 64bit. */
		case PT_ABSTIME: /* An absolute time interval. Seconds from epoch * 10^9  + nanoseconds. 64bit. */
		case PT_DOUBLE:	 /* this is a double precision floating point number. */
            u64_arg = va_arg(ap, uint64_t);
            param_buf = &u64_arg;
            param_size = 8;
			break;

		case PT_CHARBUF:   /* A printable buffer of bytes, NULL terminated */
		case PT_FSPATH:	   /* A string containing a relative or absolute file system path, null terminated */
		case PT_FSRELPATH: /* A path relative to a dirfd. */
            param_buf = va_arg(ap, char*);
            param_size = strlen(param_buf) + 1;

			break;
		case PT_BYTEBUF: /* A raw buffer of bytes not suitable for printing */

			break;
#if 0
		case PT_SOCKADDR:  /* A sockaddr structure, 1byte family + data */
            // XXX PROBABLY WRONG
            void *sarg = va_arg(ap, void*); // XXX maybe check the right type
            param_buf = &sarg;
            param_size = 1 + 12;

            break;
		case PT_SOCKTUPLE: /* A sockaddr tuple,1byte family + 12byte data + 12byte data */
            void *s2arg = va_arg(ap, void*);
            param_buf = &s2arg;
            param_size = 1 + 12 + 12;

			break;
#endif
        case PT_SOCKADDR:
        case PT_SOCKTUPLE:
		case PT_NONE:
		case PT_FDLIST:		    /* A list of fds, 16bit count + count * (64bit fd + 16bit flags) */
		case PT_DYN:		    /* Type can vary depending on the context. Used for filter fields like evt.rawarg. */
		case PT_CHARBUFARRAY:	    /* Pointer to an array of strings, exported by the user events decoder. 64bit. For internal use only. */
		case PT_CHARBUF_PAIR_ARRAY: /* Pointer to an array of string pairs, exported by the user events decoder. 64bit. For internal use only. */
		case PT_IPV4NET:	    /* An IPv4 network. */
		case PT_IPV6ADDR:	    /* A 16 byte raw IPv6 address. */
		case PT_IPV6NET:	    /* An IPv6 network. */
		case PT_IPADDR:		    /* Either an IPv4 or IPv6 address. The length indicates which one it is. */
		case PT_IPNET:		    /* Either an IPv4 or IPv6 network. The length indicates which one it is. */
        case PT_MAX:
			break;		    // Not implemented yet
		}

        // don't do anything if we couldn't correctly parse the argument (or if it's unsupported)
        if(param_size == 0)
        {
            continue;
        }

        // copy the parameter into the buffer and set the size
        bufsize = scap_event_ensure_size(pevent, bufsize, len + param_size);
        memcpy(((char*)*pevent + len), param_buf, param_size);
        len = len + param_size;
        scap_syscall_event_param_lengths(*pevent)[i] = param_size;
	}
	va_end(ap);

    (*pevent)->len = len;
    return bufsize;
}

// NOTE: these belong somewhere else (in scap but I guess) but I can't really import them like this because I would get a happy circular dependency
scap_evt *scap_event_create(uint32_t nparams, const uint16_t param_lengths[])
{
	// todo sentinel ?
	uint32_t len = sizeof(scap_evt) + sizeof(uint16_t) * nparams;
	for(uint32_t i = 0; i < nparams; i++)
	{
		len += param_lengths[i];
	}

	scap_evt *evt = calloc(len, 1);
	if(evt == NULL)
	{
		return NULL;
	}

	evt->nparams = nparams;
	evt->len = len;
	memcpy(((char *)evt) + sizeof(struct ppm_evt_hdr), param_lengths, nparams * sizeof(uint16_t));

	printf("evt = %p\n", evt);

	return evt;
}

uint32_t scap_event_set_param(scap_evt *evt, uint32_t paramid, const void *buf)
{
	uint16_t *param_lengths = (uint16_t *)&evt[1];
	uint16_t param_size = param_lengths[paramid];
	printf("param %d size is %d\n", paramid, param_size);

	char *dest_buf = (char*)&param_lengths[evt->nparams];
	for(uint32_t i = 0; i < paramid; i++)
	{
		dest_buf += param_lengths[i];
	}

	memcpy(dest_buf, buf, param_size);
	return SCAP_SUCCESS;
}
