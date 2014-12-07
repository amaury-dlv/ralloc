/* vim: set noet ts=8 sw=8 : */

/* cc ralloc-server.c -o ralloc-server */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PORT            8700

#define PAGE_SIZE       0x1000

#define CMD_ALLOC	0x1
#define CMD_FREE	0x2
#define CMD_GET		0x4
#define CMD_PUT		0x5

struct request {
	unsigned cmd;
	unsigned long allocid;
	union {
		unsigned long pgoff;
		unsigned long size;
	};
};

int create_socket(uint16_t port);
int accept_client(int sock, fd_set *set);
int sock_send(int sock, char *buf, size_t len);
int sock_recv(int sock, char *buf, size_t len);

struct alloc {
	LIST_ENTRY(alloc) list;
	unsigned long id;
	void *ptr;
};

struct client {
	LIST_ENTRY(client) list;
	LIST_HEAD(alloc_list, alloc) allocs;
	int sock;
};

LIST_HEAD(client_list, client) clients;

struct alloc *find_alloc(struct client *client, unsigned long id)
{
	struct alloc *alloc;

	for (alloc = client->allocs.lh_first; alloc;
			alloc = alloc->list.le_next)
		if (alloc->id == id)
			break;
	return alloc;
}

struct client *find_client(int sock)
{
	struct client *client;

	for (client = clients.lh_first; client;
			client = client->list.le_next)
		if (client->sock == sock)
			break;
	return client;
}

void alloc_remove(struct alloc *alloc)
{
	free(alloc->ptr);
	LIST_REMOVE(alloc, list);
	free(alloc);
}

int handle_client_command(struct client *client)
{
	int err, sock = client->sock;
	struct request r;
	struct alloc *alloc;

	sock_recv(sock, (char *) &r, sizeof(r));

	switch (r.cmd) {
	case CMD_FREE:
		alloc = find_alloc(client, r.allocid);
		if (!alloc) return -1;
		printf("freeing alloc for client %d (id=%lx)\n",
				client->sock, alloc->id);
		alloc_remove(alloc);
		break;

	case CMD_ALLOC:
		alloc = malloc(sizeof(struct alloc));
		if (!alloc) goto allocfail;
		alloc->ptr = malloc(r.size);
		if (!alloc->ptr) goto allocfail;
		alloc->id = r.allocid;
		LIST_INSERT_HEAD(&client->allocs, alloc, list);
		printf("alloc'ed %zu bytes at %p for client %d (id=%lx)\n",
				r.size, alloc->ptr, client->sock, alloc->id);
		break;

	case CMD_GET:
		alloc = find_alloc(client, r.allocid);
		if (!alloc) return -1;
		err = sock_send(sock, alloc->ptr + (PAGE_SIZE * (r.pgoff - 1)),
				PAGE_SIZE);
		if (err) return -1;
		break;

	case CMD_PUT:
		alloc = find_alloc(client, r.allocid);
		if (!alloc) return -1;
		err = sock_recv(sock, alloc->ptr + (PAGE_SIZE * (r.pgoff - 1)),
				PAGE_SIZE);
		if (err) return -1;
		break;

	default:
		return -1;
	}

	return 0;

allocfail:
	perror("malloc");
	exit(1);
}

void client_remove(struct client *client)
{
	int sock = client->sock;

	close(sock);
	LIST_REMOVE(client, list);
	free(client);
}

int main(int argc, char **argv)
{
	int sock, i;
	fd_set active_set, read_set;
	struct client *client;

	LIST_INIT(&clients);

	sock = create_socket(PORT);
	if (listen(sock, 1) < 0) {
		perror("listen");
		exit(1);
	}

	FD_ZERO(&active_set);
	FD_SET(sock, &active_set);
	for (;;) {
		read_set = active_set;
		if (select(FD_SETSIZE, &read_set, NULL, NULL, NULL) < 0) {
			perror("select");
			exit(1);
		}
		for (i = 0; i < FD_SETSIZE; ++i) {
			if (!FD_ISSET(i, &read_set))
				continue;
			if (i == sock) {
				if (accept_client(sock, &active_set))
					printf("error on connect\n");
			} else {
				client = find_client(i);
				if (handle_client_command(client)) {
					printf("client %d disconnected\n",
							client->sock);
					client_remove(client);
					FD_CLR(i, &active_set);
				}
			}
		}
	}
	return 0;
}

int sock_send(int sock, char *buf, size_t len)
{
	ssize_t err;
	size_t n = 0;

	while (n < len) {
		err = send(sock, buf + n, len - n, 0);
		if (err < 0) {
			perror("recv");
			return err;
		} else
			n += err;
	}
	return 0;
}

int sock_recv(int sock, char *buf, size_t len)
{
	ssize_t err;
	size_t n = 0;

	while (n < len) {
		err = recv(sock, buf + n, len - n, 0);
		if (err < 0) {
			perror("recv");
			return err;
		} else if (err == 0) {
			return -1;
		} else
			n += err;
	}
	return 0;
}

int accept_client(int sock, fd_set *set)
{
	int new;
	socklen_t size;
	struct sockaddr_in clientname;
	struct client *client;

	size = sizeof(clientname);
	new = accept(sock, (struct sockaddr *) &clientname,
			&size);
	if (new < 0) {
		perror("accept");
		exit(1);
	}
	printf("client %d connected from host %s\n",
			new, inet_ntoa(clientname.sin_addr));
	FD_SET(new, set);

	client = malloc(sizeof(struct client));
	if (!client) {
		perror("malloc");
		exit(1);
	}

	client->sock = new;
	LIST_INIT(&client->allocs);
	LIST_INSERT_HEAD(&clients, client, list);

	return 0;
}

int create_socket(uint16_t port)
{
	int sock, opt = 1;
	struct sockaddr_in name;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(1);
	}

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	name.sin_family = AF_INET;
	name.sin_port = htons(port);
	name.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock, (struct sockaddr *) &name, sizeof(name)) < 0) {
		perror ("bind");
		exit(1);
	}
	return sock;
}
