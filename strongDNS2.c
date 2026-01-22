/*
 * Copyright (c) 2025 hrimfaxi(outmatch@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "config.h"

#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

#define ARRAY_SIZE(n)     (sizeof(n) / sizeof(n[0]))
#define LOG_ERR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define ASSERT(cond)                                                                                                           \
	do {                                                                                                                   \
		if (!(cond)) {                                                                                                 \
			LOG_ERR("[%s: %d]: Assertion failed: %s\n", __FILE__, __LINE__, #cond);                                \
			goto out;                                                                                              \
		}                                                                                                              \
	} while (0)

#define IPV4_LIST_FN     DATA_PREFIX "/ipv4.txt"
#define IPV6_LIST_FN     DATA_PREFIX "/ipv6.txt"
#define QUEUE_NUM        1
#define IPV4_BUCKET_SIZE 512
#define IPV6_BUCKET_SIZE 64
#define MAX_DNS_NAME_LEN 255
#define MAX_JUMP_COUNT   10

uint32_t XXH32(void const *const input, size_t const length, uint32_t const seed);

typedef struct
{
	bool        debug;
	bool        short_video_mark;
	bool        youtube_mark;
	uint16_t    queue_num;
	uint32_t    ipv4_bucket_size;
	uint32_t    ipv6_bucket_size;
	const char *ipv4_list_fn;
	const char *ipv6_list_fn;
} Config;

Config CONFIG = {
	.debug            = false,
	.short_video_mark = false,
	.youtube_mark     = false,
	.queue_num        = QUEUE_NUM,
	.ipv4_list_fn     = IPV4_LIST_FN,
	.ipv6_list_fn     = IPV6_LIST_FN,
	.ipv4_bucket_size = IPV4_BUCKET_SIZE,
	.ipv6_bucket_size = IPV6_BUCKET_SIZE,
};

struct dnshdr
{
	uint16_t id;
	uint16_t flags;
	uint16_t nques;
	uint16_t nanswer;
	uint16_t nauth;
	uint16_t naddi;
} __packed;

void hexdump(const void *data, size_t size) {
	const uint8_t *byte_data = (const uint8_t *) data;
	size_t         offset    = 0;

	while (offset < size) {
		// 打印偏移地址
		printf("%08lx  ", (unsigned long) offset);

		// 打印十六进制数据
		for (size_t i = 0; i < 16; ++i) {
			if (offset + i < size) {
				printf("%02x ", byte_data[offset + i]);
			} else {
				printf("   "); // 对齐空格
			}
			if (i == 7) {
				printf(" "); // 中间分割
			}
		}

		// 打印 ASCII 表示
		printf(" |");
		for (size_t i = 0; i < 16; ++i) {
			if (offset + i < size) {
				unsigned char c = byte_data[offset + i];
				printf("%c", isprint(c) ? c : '.'); // 可打印字符直接输出，不可打印字符用 `.` 表示
			} else {
				printf(" ");
			}
		}
		printf("|\n");

		offset += 16;
	}
}

// 通用链表节点结构，带灵活数组成员
typedef struct HashNode
{
	struct HashNode *next;    // 指向下一个节点
	uint8_t          data[0]; // 存储 key 的灵活数组
} HashNode;

// 通用哈希表结构
typedef struct HashTable
{
	uint32_t   bucket_size;                                         // 哈希桶大小
	uint32_t   seed;                                                // 哈希种子
	HashNode **buckets;                                             // 哈希表
	uint32_t (*hash_func)(struct HashTable *hash, const void *key); // 哈希函数
	bool (*cmp_func)(const void *key1, const void *key2);           // 比较函数
	size_t key_size;                                                // key 的大小
} HashTable;

// 判断一个数是否是 2 的幂
static inline bool is_power_of_two(uint32_t x) {
	return (x != 0) && ((x & (x - 1)) == 0);
}

static int get_random_bytes(void *buf, size_t nbytes) {
	ssize_t result;

#ifdef HAVE_SYS_RANDOM_H
	result = getrandom(buf, nbytes, 0);
#else
	result = -1;
#endif

	if (result == -1) {
		int fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0) {
			return fd;
		}

		result = read(fd, buf, nbytes);
		close(fd);

		if (result != (ssize_t) nbytes) {
			return -1;
		}
	} else if (result != (ssize_t) nbytes) {
		return -1;
	}

	return (int) nbytes;
}

// 初始化哈希表
HashTable *hash_table_init(uint32_t bucket_size, size_t key_size,
			   uint32_t (*hash_func)(struct HashTable *hash, const void *key),
			   bool (*cmp_func)(const void *key1, const void *key2)) {
	uint32_t seed;

	if (get_random_bytes(&seed, sizeof(seed)) < 0) {
		LOG_ERR("cannot generate hash table seed\n");
		return NULL;
	}

	// 检查 bucket_size 是否是 2 的幂
	if (!is_power_of_two(bucket_size)) {
		LOG_ERR("bucket_size must be a power of 2\n");
		return NULL;
	}

	HashNode **buckets = (typeof(buckets)) calloc(bucket_size, sizeof(*buckets));
	if (!buckets) {
		LOG_ERR("failed to allocate memory for hash buckets\n");
		return NULL;
	}

	HashTable *table = (typeof(table)) malloc(sizeof(*table));
	if (!table) {
		LOG_ERR("failed to allocate memory for hash table\n");
		free(buckets);
		return NULL;
	}

	*table = (typeof(*table)) {
		.bucket_size = bucket_size,
		.seed        = seed,
		.key_size    = key_size,
		.hash_func   = hash_func,
		.cmp_func    = cmp_func,
		.buckets     = buckets,
	};

	return table;
}

// 向哈希表添加元素
void hash_table_add(HashTable *table, const void *key) {
	uint32_t hash  = table->hash_func(table, key);
	uint32_t index = hash & (table->bucket_size - 1);

	// 检查是否已存在
	HashNode *current = table->buckets[index];
	while (current) {
		void *current_key = current->data; // key 位于 data 的开始
		if (table->cmp_func(current_key, key)) {
			LOG_ERR("warning: duplicated entry\n");
			return;
		}
		current = current->next;
	}

	// 分配新节点
	size_t    node_size = offsetof(HashNode, data) + table->key_size;
	HashNode *new_node  = (typeof(new_node)) malloc(node_size);
	if (!new_node) {
		LOG_ERR("failed to allocate memory for new node\n");
		exit(EXIT_FAILURE);
	}

	// 将 key 写入节点
	memcpy(new_node->data, key, table->key_size);

	// 插入到链表头部
	new_node->next        = table->buckets[index];
	table->buckets[index] = new_node;
}

// 检查是否在哈希表中
bool hash_table_contains(HashTable *table, const void *key) {
	uint32_t hash  = table->hash_func(table, key);
	uint32_t index = hash & (table->bucket_size - 1);

	HashNode *current = table->buckets[index];
	while (current) {
		void *current_key = current->data; // key 位于 data 的开始
		if (table->cmp_func(current_key, key)) {
			return true; // 找到
		}
		current = current->next;
	}
	return false; // 未找到
}

// 清理哈希表
void hash_table_free(HashTable *table) {
	for (uint32_t i = 0; i < table->bucket_size; i++) {
		HashNode *current = table->buckets[i];

		while (current) {
			HashNode *temp = current;
			current        = current->next;
			free(temp);
		}
	}
	free(table->buckets);
	free(table);
}

void print_hash_stat(HashTable *table) {
	size_t cnt, max_cnt = 0;

	printf("Hash table: %p\n", table);
	for (uint32_t i = 0; i < table->bucket_size; i++) {
		HashNode *current = table->buckets[i];

		cnt = 0;
		while (current) {
			current = current->next;
			cnt++;
		}

		printf("Hash [%03u]: %02zu elements\n", i, cnt);
		if (max_cnt < cnt)
			max_cnt = cnt;
	}

	printf("max element count: %03zu\n", max_cnt);
}

uint32_t ipv4_hash_function(HashTable *table, const void *key) {
	return XXH32(key, sizeof(struct in_addr), table->seed);
}

bool ipv4_cmp_function(const void *key1, const void *key2) {
	return memcmp(key1, key2, sizeof(struct in_addr)) == 0;
}

uint32_t ipv6_hash_function(HashTable *table, const void *key) {
	return XXH32(key, sizeof(struct in6_addr), table->seed);
}

bool ipv6_cmp_function(const void *key1, const void *key2) {
	return memcmp(key1, key2, sizeof(struct in6_addr)) == 0;
}

// 判断是否是 2001::xxxx:yyyy 格式的 IPv6 地址
// gfw开始投毒以上ipv6地址
static bool is_gfw_ipv6(const struct in6_addr *addr) {
	const uint8_t *bytes = addr->s6_addr; // IPv6 地址的字节数组表示

	// 检查前两字节是否是 0x2001
	if (bytes[0] != 0x20 || bytes[1] != 0x01) {
		return false; // 前缀不是 2001，直接返回
	}

	// 检查中间字节是否全是 0（bytes[2] 到 bytes[11]）
	for (int i = 2; i < 12; i++) {
		if (bytes[i]) {
			return false; // 如果中间任何一个字节不是 0，返回 false
		}
	}

	// 如果前缀和中间字节都符合条件，返回 true
	return true;
}

HashTable *ipv4_table = NULL;
HashTable *ipv6_table = NULL;

static const uint8_t *skip_dns_name(const uint8_t *p, const uint8_t *end) {
	bool compressed = false;

	while (p < end && *p != '\0') {
		uint8_t label_len = *p;

		if ((label_len & 0xC0) == 0xC0) {
			p += 2;
			compressed = true;
			break;
		} else {
			const int domain_len = 1 + (int) label_len; // 包括长度字符本身
			p += domain_len;
		}
	}

	if (p >= end)
		return NULL;

	if (!compressed && *p == '\0') // 检查是否是完整域名的结束符
		p++;                   // 跳过域名结束的 0 字节
	return p;
}

static int get_dns_name(const uint8_t *dns, size_t dns_len, const uint8_t *name, char *domain, size_t max_domain_len) {
	const uint8_t *p;
	const uint8_t *end        = dns + dns_len;
	int            jump_count = 0;
	size_t         domain_pos = 0;
	const uint8_t *name_end   = NULL; // 记录域名结束位置

	if (!dns || dns_len < sizeof(struct dnshdr) || !name || !domain || !max_domain_len) {
		return -1;
	}

	if (name < dns || name >= end)
		return -1;

	p         = name;
	domain[0] = '\0';

	while (p < end) {
		uint8_t label_len = *p;

		if ((label_len & 0xC0) == 0xC0) {
			// 压缩指针处理
			if (p + 2 > end) {
				return -1;
			}

			// 如果第一次遇到压缩指针，记录当前位置作为结束位置
			if (!name_end) {
				name_end = p + 2; // 压缩指针占2字节，之后就是下一个字段
			}

			// 安全读取偏移量
			uint16_t offset = ((p[0] & 0x3F) << 8) | p[1];
			if (offset >= dns_len) {
				return -1;
			}

			p = dns + offset;
			jump_count++;

			if (jump_count > MAX_JUMP_COUNT) {
				return -1;
			}
		} else {
			// 普通标签处理
			if (!label_len) {
				// 记录域名结束位置（如果没有遇到过压缩指针）
				if (!name_end) {
					name_end = p + 1; // +1 跳过结束字节
				}
				break;
			}

			if (label_len > 63 || p + label_len + 1 > end) {
				return -1;
			}

			// 确保缓冲区足够大
			if (domain_pos + label_len + 2 <= max_domain_len) { // +2 for '.' 和 '\0'
				memcpy(&domain[domain_pos], p + 1, label_len);
				domain_pos += label_len;
				domain[domain_pos++] = '.';
			} else {
				return -1;
			}

			p += label_len + 1;
		}
	}

	if (p > end || !name_end || name_end > end) {
		return -1;
	}

	// 处理域名终止符
	if (domain_pos) {
		// 截断最大域名
		if (domain_pos == max_domain_len) {
			domain[domain_pos - 1] = '\0';
		}

		size_t last = strlen(domain);
		if (last && domain[last - 1] == '.')
			domain[last - 1] = '\0';
	} else {
		// 空域名情况
		if (max_domain_len > 0) {
			domain[0] = '\0';
		} else {
			return -1;
		}
	}

	// 返回域名结束后的偏移量
	return (int) (name_end - name);
}

static int add_nftable_ipset(const char *table_name, char *ipset_name, char *ip_addr) {
	pid_t pid = fork();

	if (pid == -1) {
		perror("fork");
		return -1;
	} else if (pid == 0) {
		char *fmt_ip_addr;

		if (asprintf(&fmt_ip_addr, "{ %s }", ip_addr) < 0)
			return -1;

		char *const argv[] = {
			"/usr/sbin/nft", "add", "element", "inet", (char *) table_name, ipset_name, fmt_ip_addr, NULL,
		};

		execve(argv[0], argv, NULL);
		perror("execve");
		exit(1);
	}

	int status;

	if (waitpid(pid, &status, 0) == -1) {
		perror("wait");
		return -1;
	}

	return WIFEXITED(status) ? 0 : -1;
}

static const char *short_video_sites[] = {
	"amemv.com",
	"baijiahao.baidu.com",
	"bdurl.net",
	"bytedance.net",
	"dm.toutiao.com",
	"douyin.com",
	"douyincdn.com",
	"douyincdn.com",
	"gifshow.com",
	"haokan.baidu.com",
	"hs.ixigua.com",
	"hs.pstatp.com",
	"huawei.com",
	"huaweicloud.com",
	"huoshan.com",
	"ixigua.com",
	"ixiguavideo.com",
	"ksapisrv.com",
	"kuaishou.com",
	"kuaishoupay.com",
	"meipai.com",
	"miaopai.com",
	"qupai.me",
	"snssdk.com",
	"tieba.baidu.com",
	"tieba.com",
	"tiktokv.com",
	"toutiao.com",
	"kandian.qq.com",
	"weishi.qq.com",
	"xiongzhang.baidu.com",
	"yximgs.com",
	"sns-video-ak.xhscdn.com",
	"tiktok.com",
	"xiaohongshu.com",
	"toutiao.com",
	"snssdk",
	"douyin",
	"toutiao",
	"ixigua",
	"365yg",
	"amemv",
	"weishi.qq.com",
	"tiktok",
	"xhscdn.com",
	"gitv.tv",
	"aisee.tv",
	"atianqi.com",
	NULL,
};

static bool is_short_video_site(const char *domain_name) {
	for (const char **domain = short_video_sites; *domain != NULL; domain++) {
		if (strstr(domain_name, *domain))
			return true;
	}

	return false;
}

static const char *youtube_sites[] = {
	"googlevideo.com",
	"youtubei.googleapis.com",
	"youtube.googleapis.com",
	"youtu.be",
	"youtube-nocookie.com",
	"youtubeembeddedplayer.googleapis.com",
	"withyoutube.com",
	"youtubekids.com",
	"youtubegaming.com",
	"youtubefanfest.com",
	"youtubeeducation.com",
	"ytimg.com",
	"ggpht.com",
	"1e100.net",
	NULL,
};

static bool is_youtube_site(const char *domain_name) {
	for (const char **domain = youtube_sites; *domain != NULL; domain++) {
		if (strstr(domain_name, *domain))
			return true;
	}

	return false;
}

typedef union
{
	struct in_addr  v4;
	struct in6_addr v6;
} NET_ADDR;

static void mark_sites(const char *nftname, bool *mark, int af, NET_ADDR *addr, const char *domain_name,
		       const char *answer_domain, bool (*test)(const char *)) {
	if (*mark && af && test(domain_name)) {
		char ipaddr_str[INET6_ADDRSTRLEN];

		if (inet_ntop(af, addr, ipaddr_str, sizeof(ipaddr_str))) {
			if (CONFIG.debug) {
				LOG_ERR("[%s] %s: %s (answer name: %s) add to %s...\n", af == AF_INET ? "IPv4" : "IPv6",
					domain_name, ipaddr_str, answer_domain, nftname);
			}

			int err = add_nftable_ipset(nftname, af == AF_INET ? "spam_ips" : "spam_ips6", ipaddr_str);

			if (err) {
				LOG_ERR("ip: %s add ipset %s failed\n", ipaddr_str, nftname);
			}
		}
	}
}

static bool is_dns_polluted(const unsigned char *data, size_t len) {
	if (len < sizeof(struct iphdr) && len < sizeof(struct ip6_hdr)) {
		return false;
	}

	if (CONFIG.debug) {
		printf("packet\n");
		hexdump(data, len);
	}

	const struct iphdr   *ip_header  = (struct iphdr *) data;
	const struct ip6_hdr *ip6_header = NULL;

	size_t ip_header_len = 0;

	// 判断是否为 IPv6 数据包
	if (ip_header->version == 6) {
		ip6_header = (const struct ip6_hdr *) data;
		if (ip6_header->ip6_nxt != IPPROTO_UDP) {
			return false; // 非 UDP 协议
		}
		ip_header_len = sizeof(struct ip6_hdr);
	} else if (ip_header->version == 4) {
		if (ip_header->protocol != IPPROTO_UDP) {
			return false; // 非 UDP 协议
		}
		ip_header_len = ip_header->ihl * 4; // IPv4 报头长度
	} else {
		return false; // 非 IPv4/IPv6 数据包
	}

	// 检查 IP 报头长度合法性
	if (len < ip_header_len + sizeof(struct udphdr)) {
		return false; // 数据长度不足以包含 UDP 报头
	}

	const struct udphdr *udp_header = (struct udphdr *) (data + ip_header_len);

	// 偏移到 DNS 数据部分
	const uint8_t *dns_data = (uint8_t *) (udp_header + 1);
	size_t         dns_len  = len - ip_header_len - sizeof(struct udphdr);

	if (dns_len < sizeof(struct dnshdr)) {
		return false; // DNS 报头长度不足
	}

	const uint8_t *end = dns_data + dns_len;

	if (CONFIG.debug) {
		printf("dns_data\n");
		hexdump(dns_data, dns_len);
	}

	char domain_name[MAX_DNS_NAME_LEN];
	// 跳过 DNS 报头和问题部分，定位到应答部分
	const uint8_t *p = dns_data + sizeof(struct dnshdr);
	int            l = get_dns_name(dns_data, dns_len, p, domain_name, sizeof(domain_name));

	if (l < 0)
		return false;

	if (CONFIG.debug) {
		printf("domain name: %s\n", domain_name);
	}

	// 跳过 TYPE(2字节) 和 CLASS(2字节)
	p += l + 4;

	if (p >= end)
		return false;

	// 现在 p 指向应答部分
	const unsigned char *answer_section = p;
	bool                 result         = false;

	if (CONFIG.debug) {
		printf("answer_section\n");
		hexdump(answer_section, (size_t) (end - answer_section));
	}

	// 遍历应答部分，提取 A 记录
	while (answer_section + 12 <= end) {
		char answer_domain[MAX_DNS_NAME_LEN];

		if (get_dns_name(dns_data, dns_len, answer_section, answer_domain, sizeof(answer_domain)) < 0) {
			answer_domain[0] = '\0';
		}

		p = skip_dns_name(answer_section, end);
		if (!p)
			break;

		if (p + 10 > end) {
			break;
		}

		uint16_t type     = ntohs(*(uint16_t *) (p));
		uint16_t data_len = ntohs(*(uint16_t *) (p + 8));
		p += 10; // 跳过 TYPE、CLASS、TTL 和 RDLENGTH

		if (CONFIG.debug) {
			printf("type: %d, data_len: %d\n", type, data_len);
		}

		// 检查 RDATA 的长度是否超出剩余数据
		if (p + data_len > end)
			break;

		NET_ADDR ip_addr;
		int      af = 0;

		// 如果是 A 记录（type == 1），提取 IP 地址
		if (type == 1 && data_len == sizeof(struct in_addr)) {
			af = AF_INET;
			memcpy(&ip_addr.v4, p, sizeof(ip_addr.v4));
		} else if (type == 28 && data_len == sizeof(struct in6_addr)) {
			// AAAA记录
			af = AF_INET6;
			memcpy(&ip_addr.v6, p, sizeof(ip_addr.v6));
			result = is_gfw_ipv6(&ip_addr.v6);
			if (result)
				goto out;
		}

		if (af)
			result = hash_table_contains(af == AF_INET ? ipv4_table : ipv6_table, &ip_addr);
	out:
		if (result) {
			if (CONFIG.debug) {
				char ipaddr_str[INET6_ADDRSTRLEN];

				if (inet_ntop(af, &ip_addr, ipaddr_str, sizeof(ipaddr_str)))
					LOG_ERR("[%s] %s: %s polluted, dropping...\n", af == AF_INET ? "IPv4" : "IPv6",
						domain_name, ipaddr_str);
			}
			break;
		}

		mark_sites("douyin", &CONFIG.short_video_mark, af, &ip_addr, domain_name, answer_domain, is_short_video_site);
		mark_sites("youtube", &CONFIG.youtube_mark, af, &ip_addr, domain_name, answer_domain, is_youtube_site);
		answer_section = p + data_len; // 跳过当前应答部分
	}

	return result;
}

static int packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	struct nfqnl_msg_packet_hdr *ph          = nfq_get_msg_packet_hdr(nfa);
	unsigned char               *packet_data = NULL;
	int                          len         = nfq_get_payload(nfa, &packet_data);
	if (len < 0)
		return len;

	(void) data, (void) nfmsg;
	uint32_t id      = ntohl(ph->packet_id);
	uint32_t verdict = NF_ACCEPT;

	if (is_dns_polluted(packet_data, (size_t) len)) {
		verdict = NF_DROP;
	}

	return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

static void print_usage(const char *program_name) {
	printf("Usage: %s [-d] [-q queue_num] [-4 ipv4_list] [-6 ipv6-list] [-b ipv4_bucket_size] [-B ipv6_bucket_size] [-s]\n",
	       program_name);
	printf("  -d    Enable debug mode\n");
	printf("  -q    queue_num        netfilter queue number (Default: %d)\n", QUEUE_NUM);
	printf("  -4    ipv4_list_fn     polluted IPV4 list file path (Default: %s)\n", IPV4_LIST_FN);
	printf("  -6    ipv6_list_fn     polluted IPv6 list file path (Default: %s)\n", IPV6_LIST_FN);
	printf("  -b    ipv4_bucket_size IPv4 hash bucket size (Default: %d)\n", IPV4_BUCKET_SIZE);
	printf("  -B    ipv6_bucket_size IPv6 hash bucket size (Default: %d)\n", IPV6_BUCKET_SIZE);
	printf("  -s                     Mark short video sites (Default: disabled)\n");
	printf("  -y                     Mark youtube sites (Default: disabled)\n");
}

static int parse_line(const char *description, const char *file_path, void (*callback)(void *data, const char *line),
		      void *data) __attribute__((nonnull(1, 2, 3, 4)));

static int parse_line(const char *description, const char *file_path, void (*callback)(void *data, const char *line),
		      void *data) {
	FILE      *fp;
	char       line[1024];
	uint32_t   cnt              = 0;
	const char filtered_chars[] = " \t#\r\n";

	fp = fopen(file_path, "r");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		line[sizeof(line) - 1] = '\0';
		for (const char *p = filtered_chars; *p; p++) {
			char *found = strchr(line, *p);
			if (found)
				*found = '\0';
		}

		if (!line[0])
			continue;

#if 0
		if (CONFIG.debug) {
			printf("%s: add line %s\n", __func__, line);
		}
#endif

		(*callback)(data, line);
		cnt++;
	}

	LOG_ERR("%s: %u entries loaded.\n", description, cnt);
	fclose(fp);
	return 0;
}

static void load_ipv4_callback(void *data, const char *line) {
	HashTable     *ip_list = (typeof(ip_list)) data;
	struct in_addr addr;

	if (inet_pton(AF_INET, line, &addr) != 1) {
		LOG_ERR("invalid IP address: %s\n", line);
		return;
	}

	hash_table_add(ip_list, &addr);
}

static int load_ipv4(HashTable *ip_list, const char *list_fn) {
	return parse_line(__func__, list_fn, load_ipv4_callback, ip_list);
}

static void load_ipv6_callback(void *data, const char *line) {
	HashTable      *ip_list = (typeof(ip_list)) data;
	struct in6_addr addr;

	if (inet_pton(AF_INET6, line, &addr) != 1) {
		LOG_ERR("invalid IPv6 address: %s\n", line);
		return;
	}

	hash_table_add(ip_list, &addr);
}

static int load_ipv6(HashTable *ip_list, const char *list_fn) {
	return parse_line(__func__, list_fn, load_ipv6_callback, ip_list);
}

volatile sig_atomic_t exit_flag = false;

static void handle_signal(int sig) {
	if (sig == SIGINT || sig == SIGTERM) {
		exit_flag = 1;
	}
}

int main(int argc, char **argv) {
	struct nfq_handle   *h  = NULL;
	struct nfq_q_handle *qh = NULL;
	char                 buf[4096];
	int                  opt, ret = 0;

	// 使用 getopt 解析命令行参数
	while ((opt = getopt(argc, argv, "dq:4:6:b:B:syh")) != -1) {
		switch (opt) {
		case 'd': // 处理 -d 参数
			CONFIG.debug = true;
			break;
		case 'q':
			CONFIG.queue_num = (uint16_t) strtoul(optarg, NULL, 0);
			break;
		case '4':
			CONFIG.ipv4_list_fn = optarg;
			break;
		case '6':
			CONFIG.ipv6_list_fn = optarg;
			break;
		case 'b':
			CONFIG.ipv4_bucket_size = (uint32_t) strtoul(optarg, NULL, 0);
			break;
		case 'B':
			CONFIG.ipv6_bucket_size = (uint32_t) strtoul(optarg, NULL, 0);
			break;
		case 's':
			CONFIG.short_video_mark = true;
			break;
		case 'y':
			CONFIG.youtube_mark = true;
			break;
		case '?':
		case 'h':
		default:
			print_usage(argv[0]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	ipv4_table = hash_table_init(CONFIG.ipv4_bucket_size, sizeof(struct in_addr), ipv4_hash_function, ipv4_cmp_function);
	if (!ipv4_table) {
		LOG_ERR("failed to initialize IPv4 hash table\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	ipv6_table = hash_table_init(CONFIG.ipv6_bucket_size, sizeof(struct in6_addr), ipv6_hash_function, ipv6_cmp_function);
	if (!ipv6_table) {
		LOG_ERR("failed to initialize IPv6 hash table\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (load_ipv4(ipv4_table, CONFIG.ipv4_list_fn) < 0) {
		LOG_ERR("failed to load polluted list %s: %s\n", CONFIG.ipv4_list_fn, strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

	if (load_ipv6(ipv6_table, CONFIG.ipv6_list_fn) < 0) {
		LOG_ERR("failed to load polluted list %s: %s\n", CONFIG.ipv6_list_fn, strerror(errno));
		ret = EXIT_FAILURE;
		goto out;
	}

#if 0
	if (CONFIG.debug) {
		print_hash_stat(ipv4_table);
		print_hash_stat(ipv6_table);
	}
#endif

	ASSERT((h = nfq_open()) != NULL);
	ASSERT(nfq_unbind_pf(h, AF_INET) == 0);
	ASSERT(nfq_bind_pf(h, AF_INET) == 0);

	ASSERT((qh = nfq_create_queue(h, CONFIG.queue_num, &packet_callback, NULL)) != NULL);
	ASSERT(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) == 0);

	struct timeval timeout = {
		.tv_sec  = 1,
		.tv_usec = 0,
	};
	ASSERT(setsockopt(nfq_fd(h), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	while (!exit_flag) {
		ssize_t rv = recv(nfq_fd(h), buf, sizeof(buf), 0);
		if (rv >= 0) {
			nfq_handle_packet(h, buf, (int) rv);
		} else {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			}
			if (errno == EINTR) {
				ret = 0;
				break;
			}

			perror("recv");
			ret = EXIT_FAILURE;
			break;
		}
	}

	LOG_ERR("quitting\n");

out:
	if (qh)
		nfq_destroy_queue(qh);
	if (h)
		nfq_close(h);
	if (ipv4_table)
		hash_table_free(ipv4_table);
	if (ipv6_table)
		hash_table_free(ipv6_table);

	return ret;
}
