#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <stdint.h>


struct dnshdr
{   
	uint16_t id;
  	uint16_t flags;
  	uint16_t nques;
  	uint16_t nanswer;
  	uint16_t nauth;
  	uint16_t naddi;
};



static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph;
    assert((ph = nfq_get_msg_packet_hdr(nfa)) != NULL);
    nfq_get_payload(nfa,(unsigned char **)&data);
    u_int32_t id = ntohl(ph->packet_id);

    struct dnshdr * dnsh = (void *)data + sizeof(struct iphdr) + sizeof(struct udphdr);

    if(ntohs(dnsh->naddi) == 0)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    char buf[4096];

    assert((h = nfq_open()) != NULL);
    assert(nfq_unbind_pf(h, AF_INET) == 0);
    assert(nfq_bind_pf(h, AF_INET) == 0);

    assert((qh = nfq_create_queue(h, 1, &cb, NULL)) != NULL);
    assert(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) == 0);

    
    for(int rv; (rv = recv(nfq_fd(h), buf, sizeof(buf), 0)) && rv >= 0;)
        nfq_handle_packet(h, buf, rv);
    
    nfq_destroy_queue(qh);

    nfq_close(h);
    return 0;
}
