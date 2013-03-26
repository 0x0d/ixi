#ifndef _NET_H_
#define _NET_H_

#include <linux/netdevice.h>
#include <linux/if.h>

void install_packet_type(struct packet_type *);
void uninstall_packet_type(struct packet_type *);

#endif
