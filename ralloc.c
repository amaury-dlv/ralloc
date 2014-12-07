/* vim: set noet ts=8 sw=8 : */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/socket.h>
#include <linux/highmem.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/ip.h>

#define RALLOC_BASE 0x1000

#define RALLOC_CMD_ALLOC 0x1
#define RALLOC_CMD_FREE  0x2
#define RALLOC_CMD_GET   0x4
#define RALLOC_CMD_PUT   0x5

/*
 * Ralloc configuration
 */
static unsigned long ralloc_base = RALLOC_BASE;

/*
 * Describes a remotely allocated memory area
 */
struct remote_vma_struct {
	struct socket *sock;
	struct vm_area_struct *vma;
	unsigned long alloc_id;
	unsigned long pfn;
	pgoff_t pgoff;
};

struct ralloc_request {
	unsigned cmd;
	unsigned long alloc_id;
	union {
		unsigned long pgoff;
		unsigned long size;
	};
};

static ssize_t recv(struct socket *sock, void *dst, size_t len);
static ssize_t send(struct socket *sock, void *src, size_t len);

static void copy_to_page(struct page *dst, const void *src, int len)
{
	void *kaddr = kmap_atomic(dst);
	memcpy(kaddr, src, len);
	kunmap_atomic(kaddr);
}

static void copy_from_page(struct page *src, void *dst, int len)
{
	void *kaddr = kmap_atomic(src);
	memcpy(dst, kaddr, len);
	kunmap_atomic(kaddr);
}

static int __rvma_flush(struct remote_vma_struct *rvma, struct page *page)
{
	int err;
	char *pagebuf;
	struct ralloc_request req = {
		.cmd = RALLOC_CMD_PUT,
		.alloc_id = rvma->alloc_id,
		.pgoff = rvma->pgoff,
	};

	err = send(rvma->sock, &req, sizeof(struct ralloc_request));
	if (err)
		return err;

	pagebuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!pagebuf)
		return -ENOMEM;

	copy_from_page(page, pagebuf, PAGE_SIZE);
	err = send(rvma->sock, pagebuf, PAGE_SIZE);
	kfree(pagebuf);
	return err;
}

static int rvma_flush(struct remote_vma_struct *rvma)
{
	int err = 0;
	struct page *page;

	if (rvma->pfn == ~0ul)
		return 0;
	get_user_pages(NULL, rvma->vma->vm_mm, rvma->pfn << PAGE_SHIFT,
			1, 0, 1, &page, NULL);
	zap_page_range(rvma->vma, rvma->pfn << PAGE_SHIFT, PAGE_SIZE, NULL);
	err = __rvma_flush(rvma, page);
	put_page(page);
	return err;
}

static int __rvma_update(struct remote_vma_struct *rvma, struct page *page)
{
	int err;
	char *pagebuf;
	struct ralloc_request req = {
		.cmd = RALLOC_CMD_GET,
		.alloc_id = rvma->alloc_id,
		.pgoff = rvma->pgoff,
	};

	err = send(rvma->sock, &req, sizeof(struct ralloc_request));
	if (err)
		return err;

	pagebuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!pagebuf)
		return -ENOMEM;

	err = recv(rvma->sock, pagebuf, PAGE_SIZE);
	copy_to_page(page, pagebuf, PAGE_SIZE);
	kfree(pagebuf);
	return err;
}

static int rvma_update(struct remote_vma_struct *rvma, struct vm_fault *vmf,
		struct page **ret)
{
	int err;
	struct page *page;

	*ret = NULL;
	page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, rvma->vma,
			(unsigned long) vmf->virtual_address);
	if (!page)
		return -ENOMEM;
	rvma->pfn = (unsigned long) vmf->virtual_address >> PAGE_SHIFT;
	rvma->pgoff = vmf->pgoff;
	err = __rvma_update(rvma, page);
	if (err) {
		put_page(page);
		return err;
	}
	*ret = page;
	return 0;
}

int rvma_connect(struct remote_vma_struct *rvma, const char *host, int port)
{
	int err;
	struct socket *sock;
	struct sockaddr_in *addr;
	struct sockaddr_storage addr_storage;

	sock = kmalloc(sizeof(struct socket), GFP_KERNEL);
	if (!sock) {
		err = -ENOMEM;
		goto error;
	}

	err = sock_create(PF_INET, SOCK_STREAM, 0, &sock);
	if (err)
		goto free;

	addr = (struct sockaddr_in *) &addr_storage;
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	addr->sin_addr.s_addr = in_aton(host);
	if (err) {
		pr_warn("ralloc: invalid server address\n");
		goto release;
	}
	err = sock->ops->connect(sock, (struct sockaddr *) &addr_storage,
			sizeof(struct sockaddr_in), 0);
	if (err) {
		pr_warn("ralloc: could not connect to server\n");
		goto release;
	}
	rvma->sock = sock;
	return 0;

release:
	sock_release(sock);
free:
	kfree(sock);
error:
	return err;
}

int rvma_init(struct remote_vma_struct *rvma, struct vm_area_struct *vma)
{
	memset(rvma, 0, sizeof(struct remote_vma_struct));
	rvma->vma = vma;
	rvma->pfn = ~0ul;
	rvma->alloc_id = rvma->vma->vm_start >> PAGE_SHIFT;
	return 0;
}

int rvma_alloc(struct remote_vma_struct *rvma, unsigned long size)
{
	struct ralloc_request req = {
		.cmd = RALLOC_CMD_ALLOC,
		.alloc_id = rvma->alloc_id,
		.size = size,
	};

	return send(rvma->sock, &req, sizeof(struct ralloc_request));
}

void rvma_release(struct remote_vma_struct *rvma)
{
	if (rvma->sock) {
		struct ralloc_request req = {
			.cmd = RALLOC_CMD_FREE,
			.alloc_id = rvma->alloc_id,

		};

		send(rvma->sock, &req, sizeof(struct ralloc_request));
		sock_release(rvma->sock);
		kfree(rvma->sock);
		rvma->sock = NULL;
	}
}

static void ralloc_vm_close(struct vm_area_struct *vma)
{
	struct remote_vma_struct *rvma;

	rvma = vma->vm_private_data;
	if (rvma) {
		rvma_release(rvma);
		kzfree(rvma);
	}
}


static int ralloc_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	struct remote_vma_struct *rvma = vma->vm_private_data;
	struct page *page;

#if 0
	pr_warn("ralloc: fault (vma=%p,pgoff=%ld,flags=%x,page=%p)\n",
			vmf->virtual_address, vmf->pgoff, vmf->flags,
			vmf->page);
#endif

	if (rvma->pfn != ~0ul) {
		err = rvma_flush(rvma);
		if (err)
			goto error;
	}

	rvma_update(rvma, vmf, &page);
	if (err)
		goto error;

	vmf->page = page;
	return 0;
error:
	if (err == -ENOMEM)
		return VM_FAULT_OOM;
	return VM_FAULT_SIGBUS;
}

static struct vm_operations_struct ralloc_vm_ops = {
	.close = ralloc_vm_close,
	.fault = ralloc_vm_fault,
};

SYSCALL_DEFINE3(ralloc, unsigned long, size, const char __user *, host,
		int, port)
{
	char khost[256];
	unsigned long addr;
	struct vm_unmapped_area_info info;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct remote_vma_struct *rvma;
	int err;

	if (!size || !host)
		return 0;

	memset(khost, 0, sizeof(khost));
	if (strncpy_from_user(khost, host, sizeof(khost)-1) < 0)
		return 0;
	khost[sizeof(khost)-1] = '\0';

	size = PAGE_ALIGN(size);

	info.flags = 0;
	info.length = size;
	info.low_limit = ralloc_base;
	info.high_limit = ~0;
	info.align_mask = 0;

	down_write(&mm->mmap_sem);

	addr = unmapped_area(&info);

	if (addr & ~PAGE_MASK) {
		pr_warn("ralloc: could not find unmapped area\n");
		goto error;
	}

	vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (!vma)
		goto error;

	INIT_LIST_HEAD(&vma->anon_vma_chain);
	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + size;
	vma->vm_ops = &ralloc_vm_ops;
	vma->vm_flags = VM_READ | VM_WRITE | VM_EXEC;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	vma->vm_pgoff = 0;

	err = insert_vm_struct(mm, vma);
	if (err) {
		kfree(vma);
		goto error;
	}

	rvma = kzalloc(sizeof(struct remote_vma_struct), GFP_KERNEL);
	if (!rvma)
		goto error;

	err = rvma_init(rvma, vma);
	if (err)
		goto free_rvma;
	err = rvma_connect(rvma, khost, port);
	if (err)
		goto free_rvma;

	vma->vm_private_data = rvma;

	err = rvma_alloc(rvma, size);
	if (err)
		goto release_rvma;

	up_write(&mm->mmap_sem);
	return addr;

release_rvma:
	rvma_release(rvma);
free_rvma:
	kfree(rvma);
error:
	up_write(&mm->mmap_sem);
	return 0;
}

SYSCALL_DEFINE1(rfree, unsigned long, addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int err = 0;

	down_write(&mm->mmap_sem);
	vma = find_vma(current->mm, addr);
	if (!vma)
		return -EINVAL;
	err = do_munmap(mm, vma->vm_start, vma->vm_end - vma->vm_start);
	up_write(&mm->mmap_sem);
	return err;
}

static ssize_t send(struct socket *sock, void *src, size_t len)
{
	struct msghdr msg;
	struct iovec iov;
	ssize_t size, n = 0;
	mm_segment_t mmseg;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	while (n < len) {
		iov.iov_base = src + n;
		iov.iov_len = len - n;

		mmseg = get_fs();
		set_fs(KERNEL_DS);
		size = sock_sendmsg(sock, &msg, len - n);
		set_fs(mmseg);
		if (size < 0)
			return size;
		else
			n += size;
	}
	return 0;
}

static ssize_t recv(struct socket *sock, void *dst, size_t len)
{
	struct msghdr msg;
	struct iovec iov;
	ssize_t size, n = 0;
	mm_segment_t mmseg;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	while (n < len) {
		iov.iov_base = dst;
		iov.iov_len = len;

		mmseg = get_fs();
		set_fs(KERNEL_DS);
		size = sock_recvmsg(sock, &msg, len - n, msg.msg_flags);
		set_fs(mmseg);
		if (size < 0)
			return size;
		else if (size == 0)
			return -EIO;
		else
			n += size;
	}
	return 0;
}
