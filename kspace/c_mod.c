/*
 * Copyright (c) 2021 Qubercomm Technologies, Inc.
 * All Rights Reserved.
 * Qubercomm Technologies, Inc. Confidential and Proprietary.
 */

#include<linux/module.h>
#include<linux/version.h>
#include<linux/kernel.h>
#include<linux/types.h>
#include<linux/kdev_t.h>
#include<linux/fs.h>
#include<linux/device.h>
#include<linux/cdev.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#include<linux/uaccess.h>
#else
#include<asm/uaccess.h>
#endif
#include<linux/sched.h>

static dev_t cdev_r;
static struct cdev m_cdev;
static struct class *m_cldev_ptr;

#define MAXLEN 4000		// correspond to 4k memory page size
static char mybuffer[MAXLEN];

static int urlf_open(struct inode *inode_ptr, struct file *file_ptr)
{
	pr_info("module opened");
	return 0;
}

static ssize_t urlf_read(struct file *file_ptr, char *buffer,
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

static ssize_t urlf_write(struct file *file_ptr, const char *buffer,
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
	nbytes =
	    bytes_to_write - copy_from_user(mybuffer + *offset, buffer,
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

static struct file_operations urlf_fops = {
	.owner = THIS_MODULE,
	.open = urlf_open,
	.read = urlf_read,
	.write = urlf_write,
	.llseek = urlf_lseek
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

	if (device_create(m_cldev_ptr, NULL, cdev_r, NULL, "c_mod")
	    == NULL) {
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

	return 0;
}

static void __exit exit_urlf(void)
{
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
