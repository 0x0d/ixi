#include "net.h"

void install_packet_type(struct packet_type *pkt)
{
    dev_add_pack(pkt);
}

void uninstall_packet_type(struct packet_type *pkt)
{
    dev_remove_pack(pkt);
}
