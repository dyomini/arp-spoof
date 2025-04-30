#pragma once

#pragma pack(push, 1)
struct IpHdr final
{
#if (LIBNET_LIL_ENDIAN)
  u_int8_t ip_hl : 4, /* header length */
      ip_v : 4;       /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
  u_int8_t ip_v : 4, /* version */
      ip_hl : 4;     /* header length */
#endif
  u_int8_t ip_tos; /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY 0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT 0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY 0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST 0x02
#endif
  u_int16_t ip_len; /* total length */
  u_int16_t ip_id;  /* identification */
  u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000 /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000 /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000 /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
#endif
  u_int8_t ip_ttl;               /* time to live */
  u_int8_t ip_p;                 /* protocol */
  u_int16_t ip_sum;              /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};

#pragma pack(pop)
