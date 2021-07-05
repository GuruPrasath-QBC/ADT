/*
 * Copyright (c) 2021 Qubercomm Technologies, Inc.
 * All Rights Reserved.
 * Qubercomm Technologies, Inc. Confidential and Proprietary.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif
#include <linux/sched.h>
#include <linux/hashtable.h>

#include "c_mod.h"

static dev_t cdev_r;
static struct cdev m_cdev;
static struct class *m_cldev_ptr;

#define MAXLEN 4000		// correspond to 4k memory page size
static char mybuffer[MAXLEN];

DEFINE_HASHTABLE(ctable, 4);	// 4 bit table - max 16 (=2**4) entries

static int urlf_open(struct inode *inode_ptr, struct file *file_ptr)
{
	pr_info("module opened");
	return 0;
}

static ssize_t urlf_read(struct file *file_ptr, char __user *buffer,
			 size_t length, loff_t *offset)
{
	int max_bytes;
	int bytes_to_read;
	int nbytes;

	max_bytes = MAXLEN - *offset;
	if (max_bytes > length)
		bytes_to_read = length;
	else
		bytes_to_read = max_bytes;

	if (bytes_to_read == 0) {
		pr_err("nothing to read");
		return (-ENOSPC);
	}
	nbytes =
	    bytes_to_read - copy_to_user(buffer, mybuffer + *offset,
					 bytes_to_read);

	return nbytes;
}

static ssize_t urlf_write(struct file *file_ptr, const char __user *buffer,
			  size_t length, loff_t *offset)
{
	int max_bytes;
	int bytes_to_write;
	int nbytes;

	max_bytes = MAXLEN - *offset;
	if (max_bytes > length)
		bytes_to_write = length;
	else
		bytes_to_write = max_bytes;

	if (bytes_to_write == 0) {
		pr_err("nothing to write");
		return (-ENOSPC);
	}
	nbytes = bytes_to_write - copy_from_user(mybuffer + *offset, buffer,
						 bytes_to_write);
	*offset = *offset + nbytes;

	return nbytes;
}

static loff_t urlf_lseek(struct file *file_ptr, loff_t offset, int origin)
{
	loff_t new_pos = 0;

	switch (origin) {
	case 0:
		new_pos = offset;
		break;
	case 1:
		new_pos = file_ptr->f_pos + offset;
		break;
	case 2:
		new_pos = MAXLEN - offset;
		break;
	}

	if (new_pos > MAXLEN)
		new_pos = MAXLEN;
	if (new_pos < 0)
		new_pos = 0;
	file_ptr->f_pos = new_pos;

	return new_pos;
}

static void clrctable(void)
{
	int i;
	cTe_t *e;
	struct hlist_node *tmp;

	if (ctable == NULL) {
		pr_err("urlf: %s called without init??!!", __func__);
		return;
	}

	hash_for_each_safe(ctable, i, tmp, e, node) {
		hash_del(&e->node);
		kfree(e);
	}
}

static long urlf_do_ioctl(struct file *minor, unsigned int cmd,
			  unsigned long arg)
{
	int retval = 0;
	cTe_t *ct_entry;
	struct usIO_s userdata;
	struct urlf_s *urlfdata;
	cTe_t *e;
	struct hlist_node *tmp;
	uint8_t i, read_idx;

	//char ipstr[INET_ADDRSTRLEN;

	pr_debug("urlf: ioctl cmd: 0x%x, arg: 0x%lx\n", cmd, arg);

	switch (cmd) {
	case URLF_ADD_E:
		if (copy_from_user
		    (&userdata, (struct usIO_s *)arg, sizeof(userdata))) {
			pr_err("urlf: ioctl cmd: 0x%x, cfu failed", cmd);
		} else {
			pr_info("urlf: udata ip: %ld port: %d type: %d",
				(long)userdata.ip, userdata.port,
				userdata.type);
			ct_entry = kzalloc(sizeof(*ct_entry), GFP_KERNEL);
			if (!ct_entry)
				return -ENOMEM;

			pr_debug("urlf: new cTe = %p", ct_entry);
			urlfdata = &ct_entry->d;
			pr_debug("urlf: cTe.d = %p", urlfdata);
			urlfdata->ip = userdata.ip;
			urlfdata->port = userdata.port;
			ct_entry->type = userdata.type;

			if (ctable == NULL) {
				pr_err("urlf: %s called without init??!!",
				       __func__);
				return -EACCES;
			}

			pr_debug("urlf: add cTe.node= %p to ctable= %p",
				 &ct_entry->node, ctable);
			hash_add(ctable, &ct_entry->node, ct_entry->type);
		}
		break;
	case URLF_DEL_E:
		if (copy_from_user
		    (&userdata, (struct usIO_s *)arg, sizeof(userdata))) {
			pr_err("urlf: ioctl cmd: 0x%x, cfu failed", cmd);
		} else {
			pr_info("urlf: udata ip: %ld port: %d",
				(long)userdata.ip, userdata.port);

			if (ctable == NULL) {
				pr_err("urlf: %s called without init??!!",
				       __func__);
				return -EACCES;
			}

			hash_for_each_safe(ctable, i, tmp, e, node) {
				if (e->d.ip == userdata.ip &&
				    e->d.port == userdata.port) {
					hash_del(&e->node);
					kfree(e);
				}
			}
		}
		break;
	case URLF_CLR_T:
		pr_info("urlf: ioctl cmd: 0x%x, clear table", cmd);
		clrctable();
		break;
	case URLF_READ_E:
		if (copy_from_user
		    (&read_idx, (uint8_t *)arg, sizeof(read_idx))) {
			pr_err("urlf: ioctl cmd: 0x%x, cfu failed", cmd);
		} else {
			pr_info("urlf: read_idx: %d", read_idx);

			if (ctable == NULL) {
				pr_err("urlf: %s called without init??!!",
				       __func__);
				return -EACCES;
			}

			hash_for_each_safe(ctable, i, tmp, e, node) {
				if (i == read_idx)
					break;
			}

			userdata.ip = e->d.ip;
			userdata.port = e->d.port;
			userdata.type = e->type;
			if (copy_to_user
			    ((struct usIO_s *)arg, &userdata, sizeof(userdata)))
				pr_err("urlf: ioctl ctu failed");
		}
		break;
	case URLF_MODI_E:
		// TODO
		break;
	default:
		retval = -EINVAL;
	}

	return retval;
}

static struct file_operations urlf_fops = {
	.owner = THIS_MODULE,
	.open = urlf_open,
	.read = urlf_read,
	.write = urlf_write,
	.llseek = urlf_lseek,
	.unlocked_ioctl = urlf_do_ioctl,
};

static int __init init_urlf(void)
{
	int major = 250;
	int minor = 0;

	cdev_r = MKDEV(major, minor);
	if (alloc_chrdev_region(&cdev_r, 0, 1, "QBC") < 0)
		return -1;

	m_cldev_ptr = class_create(THIS_MODULE, "cmod_class");
	if (m_cldev_ptr == NULL) {
		unregister_chrdev_region(cdev_r, 1);
		return -1;
	}

	if (device_create(m_cldev_ptr, NULL, cdev_r, NULL, "c_mod") == NULL) {
		class_destroy(m_cldev_ptr);
		unregister_chrdev_region(cdev_r, 1);
		return -1;
	}

	cdev_init(&m_cdev, &urlf_fops);
	if (cdev_add(&m_cdev, cdev_r, 1) == -1) {
		device_destroy(m_cldev_ptr, cdev_r);
		class_destroy(m_cldev_ptr);
		unregister_chrdev_region(cdev_r, 1);
		return -1;
	}

	hash_init(ctable);

	return 0;
}

static void __exit exit_urlf(void)
{
	clrctable();

	cdev_del(&m_cdev);
	device_destroy(m_cldev_ptr, cdev_r);
	class_destroy(m_cldev_ptr);
	unregister_chrdev_region(cdev_r, 1);
}

module_init(init_urlf);
module_exit(exit_urlf);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("URL Filter support");
MODULE_AUTHOR("Qubercomm Technologies");
