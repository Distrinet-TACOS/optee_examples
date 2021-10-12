#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/interrupt.h>
#include <linux/version.h>
#include <linux/errno.h>

#include <linux/tee_drv.h>
#include <linux/uuid.h>
#include <linux/kfifo.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/list.h>

#include "controller.h"
#include <console_split_public.h>

#define DRIVER_NAME "Split driver controller"

static const uuid_t pta_id = UUID_INIT(UUID1, UUID2, UUID3, UUID4, UUID5, UUID6,
				       UUID7, UUID8, UUID9, UUID10, UUID11);

// enum command { READ_CHAR, REGISTER_ITR, UNREGISTER_ITR, WRITE_CHARS };

static struct controller {
	const char *name;
	u32 sess_id;
	struct tee_context *ctx;
} contr_data = { .name = "Controller" };

#define BUFFER_SIZE 256

struct split_device {
	dev_t dev;
	const char *name;
	u32 sess_id;
	DECLARE_KFIFO(buffer, char, BUFFER_SIZE);
	// Update the device buffers with the new information.
	// For this version, only use a character array (as the devices are
	// character devices).
	void (*update)(dev_t dev);

	struct list_head list;
};
LIST_HEAD(split_devices);
static unsigned int no_devices = 0;

static void print_buf(struct update_buffer *buf)
{
	pr_info("Buffer entry: sess_id = %u, count = %u\n, first = %c",
		buf->sess_id, buf->count, buf->buf[0]);
}

static int update_buffers(struct update_buffer *buf)
{
	struct split_device *device;

	while (buf->count != 0) {
		// print_buf(buf);
		list_for_each_entry (device, &split_devices, list) {
			if (device->sess_id == buf->sess_id) {
				kfifo_in(&device->buffer, buf->buf, buf->count);
			}
		}
		buf = &buf[1];
	}

	return 0;
}

static int notification_handler(void)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];
	struct tee_shm *mem;
	struct update_buffer *buffers;
	size_t mem_size = no_devices * sizeof(struct update_buffer) * BUFFER_SIZE;
	u32 flags = TEE_SHM_MAPPED | TEE_SHM_DMA_BUF;
	struct split_device *device;

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = UPDATE_BUFFER;
	inv_arg.session = contr_data.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	// Allocating shared memory. Because of call overhead, the memory
	// reserved is as large as the maximum possible size. It might be
	// possible to call into the PTA to request the exact size, but this
	// needs to be explored further.
	mem = tee_shm_alloc(contr_data.ctx, mem_size, flags);
	if (IS_ERR(mem)) {
		pr_err("Failed to map shared memory: %lx\n", PTR_ERR(mem));
		return PTR_ERR(mem);
	}

	buffers = tee_shm_get_va(mem, 0);
	if (IS_ERR(buffers)) {
		pr_err("tee_shm_get_va failed: %lx\n", PTR_ERR(buffers));
		return PTR_ERR(buffers);
	}

	param[0].u.memref.shm = mem;
	param[0].u.memref.size = mem_size;
	param[0].u.memref.shm_offs = 0;

	ret = tee_client_invoke_func(contr_data.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("UPDATE_BUFFER invoke error: %x.\n", inv_arg.ret);
		return -EINVAL;
	}

	update_buffers(buffers);
	tee_shm_free(mem);

	list_for_each_entry (device, &split_devices, list) {
		if (!kfifo_is_empty(&device->buffer)) {
			device->update(device->dev);
		}
	}
	return 0;
}

static int open_session(const char *name, u32 *sess_id, bool create_buf)
{
	struct tee_ioctl_open_session_arg sess_arg;
	struct tee_param param[4];
	int ret;

	memset(&sess_arg, 0, sizeof(sess_arg));
	export_uuid(sess_arg.uuid, &pta_id);
	sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	sess_arg.num_params = 4;

	memset(&param, 0, sizeof(param));
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = create_buf;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	ret = tee_client_open_session(contr_data.ctx, &sess_arg, param);
	if ((ret < 0) || (sess_arg.ret != 0)) {
		pr_err("tee_client_open_session failed for device %s, err: %x\n",
		       name, sess_arg.ret);
		return -EINVAL;
	}
	*sess_id = sess_arg.session;

	return 0;
}

static int close_session(u32 sess_id)
{
	tee_client_close_session(contr_data.ctx, sess_id);
	return 0;
}

static int enable_notification(void)
{
	int ret;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = ENABLE_NOTIF;
	inv_arg.session = contr_data.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	ret = tee_client_invoke_func(contr_data.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("ENABLE_NOTIF invoke error: %x.\n", inv_arg.ret);
		return -EINVAL;
	}

	ret = register_callback(notification_handler, inv_arg.params[0].a);
	if (ret < 0) {
		pr_err("Registering notification callback resulted in error: %x\n",
		       ret);
		return ret;
	}

	return 0;
}

static int disable_notification(void)
{
	int ret;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = DISABLE_NOTIF;
	inv_arg.session = contr_data.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	ret = tee_client_invoke_func(contr_data.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("DISABLE_NOTIF invoke error: %x.\n", inv_arg.ret);
		return -EINVAL;
	}

	unregister_callback();

	return 0;
}

static int enable_interrupt(u32 sess_id)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = REGISTER_ITR;
	inv_arg.session = sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	ret = tee_client_invoke_func(contr_data.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("REGISTER_ITR invoke error: %x.\n", inv_arg.ret);
		return -EINVAL;
	}

	return 0;
}

static int disable_interrupt(u32 sess_id)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = UNREGISTER_ITR;
	inv_arg.session = sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	ret = tee_client_invoke_func(contr_data.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("UNREGISTER_ITR invoke error: %x.\n", inv_arg.ret);
		return -EINVAL;
	}

	free_irq(64, NULL);

	return 0;
}

static int optee_ctx_match(struct tee_ioctl_version_data *ver, const void *data)
{
	if (ver->impl_id == TEE_IMPL_ID_OPTEE)
		return 1;
	else
		return 0;
}

static int create_context(void)
{
	pr_info("Creating context.\n");
	contr_data.ctx =
		tee_client_open_context(NULL, optee_ctx_match, NULL, NULL);
	if (IS_ERR(contr_data.ctx))
		return -ENODEV;

	return 0;
}

static int destroy_context(void)
{
	pr_info("Destroying context.\n");
	tee_client_close_context(contr_data.ctx);

	return 0;
}

/* static int device_open(struct inode *inode, struct file *filp)
{
	// create_context();
	return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
	// destroy_context();
	return 0;
}

static int device_read(struct file *filp, char __user *buf, size_t count,
		       loff_t *offp)
{
	int ret;
	size_t bytes_copied;

	count = min(count, kfifo_len(&buffer));

	ret = kfifo_to_user(&buffer, buf, count, &bytes_copied);
	if (ret < 0) {
		pr_err("User space buffer not large enough for requested count. Bytes copied: %zu, count: %zu\n",
		       bytes_copied, count);
		return -EFAULT;
	}

	return bytes_copied;
}

static int device_write(struct file *filp, const char __user *buf, size_t count,
			loff_t *offp)
{
	int ret = 0;
	size_t bytes_left;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];
	struct tee_shm *mem;
	u32 flags = TEE_SHM_MAPPED | TEE_SHM_DMA_BUF;
	char *mem_ref;

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = WRITE_CHARS;
	inv_arg.session = dev_data.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	mem = tee_shm_alloc(dev_data.ctx, count, flags);
	if (IS_ERR(mem)) {
		pr_err("Failed to map shared memory: %lx\n", PTR_ERR(mem));
		return PTR_ERR(mem);
	}

	mem_ref = tee_shm_get_va(mem, 0);
	if (IS_ERR(mem_ref)) {
		pr_err("tee_shm_get_va failed: %lx\n", PTR_ERR(mem_ref));
		return PTR_ERR(mem_ref);
	}
	bytes_left = copy_from_user(mem_ref, buf, count);
	if (bytes_left > 0) {
		pr_err("Not all bytes could be moved from user space buffer. Bytes left: %zu\n",
		       bytes_left);
		return -EFAULT;
	}

	param[0].u.memref.shm = mem;
	param[0].u.memref.size = count;
	param[0].u.memref.shm_offs = 0;
	ret = tee_client_invoke_func(dev_data.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("WRITE_CHARS invoke error: %x from %x.\n", inv_arg.ret,
		       inv_arg.ret_origin);
		return -EINVAL;
	}

	tee_shm_free(mem);

	return count;
}

static const struct file_operations fops = { .open = device_open,
					     .release = device_release,
					     .read = device_read,
					     .write = device_write };

static int register_device(void)
{
	int ret;
	ret = alloc_chrdev_region(&dev_data.dev, 0, 1, "console-split");
	if (ret < 0) {
		pr_err("Allocating device number failed with error: %x\n", ret);
		return ret;
	}

	cdev_init(&dev_data.cdev, &fops);
	dev_data.cdev.owner = THIS_MODULE;

	ret = cdev_add(&dev_data.cdev, dev_data.dev, 1);
	if (ret < 0) {
		pr_err("Adding device number failed with error: %x\n", ret);
		return ret;
	}

	return 0;
}

static int unregister_device(void)
{
	unregister_chrdev_region(dev_data.dev, 1);
	cdev_del(&dev_data.cdev);

	return 0;
} */

static int __init controller_init(void)
{
	create_context();
	open_session(contr_data.name, &contr_data.sess_id, false);
	enable_notification();

	// register_device();

	return 0;
}

static void __exit controller_exit(void)
{
	// unregister_device();

	disable_notification();
	close_session(contr_data.sess_id);
	destroy_context();
}

module_init(controller_init);
module_exit(controller_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Tom Van Eyck");

/*************
 *    API    *
 *************/

int register_split_driver(dev_t dev, const char *name, void (*update)(dev_t dev))
{
	struct split_device *device;
	pr_info("Registering split driver.\n");

	list_for_each_entry (device, &split_devices, list) {
		if (device->dev == dev) {
			return -EINVAL;
		}
	}

	device = kcalloc(1, sizeof(struct split_device), GFP_KERNEL);
	device->dev = dev;
	device->name = name;
	device->update = update;
	INIT_KFIFO(device->buffer);

	list_add(&device->list, &split_devices);
	no_devices++;

	return 0;
}
EXPORT_SYMBOL(register_split_driver);

int unregister_split_driver(dev_t dev)
{
	struct split_device *device;
	pr_info("Unregistering split driver.\n");

	list_for_each_entry (device, &split_devices, list) {
		if (device->dev == dev) {
			list_del(&device->list);
			no_devices--;
			kfree(device);

			return 0;
		}
	}

	return -EINVAL;
}
EXPORT_SYMBOL(unregister_split_driver);

int open_optee_session(dev_t dev)
{
	struct split_device *device;

	list_for_each_entry (device, &split_devices, list) {
		if (device->dev == dev) {
			open_session(device->name, &device->sess_id, true);
			enable_interrupt(device->sess_id);

			return 0;
		}
	}

	return -EINVAL;
}
EXPORT_SYMBOL(open_optee_session);

int close_optee_session(dev_t dev)
{
	struct split_device *device;
	int ret;

	list_for_each_entry (device, &split_devices, list) {
		if (device->dev == dev && device->sess_id > 0) {
			disable_interrupt(device->sess_id);
			ret = tee_client_close_session(contr_data.ctx,
						       device->sess_id);
			return 0;
		}
	}

	return -EINVAL;
}
EXPORT_SYMBOL(close_optee_session);

int read_optee(dev_t dev, char **buf, size_t *count)
{
	struct split_device *device;
	unsigned int n;

	list_for_each_entry (device, &split_devices, list) {
		if (device->dev == dev && device->sess_id > 0) {
			*count = kfifo_len(&device->buffer);
			*buf = kmalloc(*count * sizeof(char), GFP_KERNEL);
			if (IS_ERR(*buf)) {
				pr_err("Could not allocate memory: %ld",
				       PTR_ERR(*buf));
				return PTR_ERR(*buf);
			}

			n = kfifo_out(&device->buffer, *buf, *count);
			if (n < *count) {
				pr_err("Buffer size mismatch for driver %s: %x, %x",
				       device->name, MAJOR(device->dev),
				       MINOR(device->dev));
				return -EINVAL;
			}
			return 0;
		}
	}

	return -EINVAL;
}
EXPORT_SYMBOL(read_optee);

int write_optee(dev_t dev, const char *buf, size_t count)
{
	struct split_device *device;
	bool found = false;
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];
	struct tee_shm *mem;
	u32 flags = TEE_SHM_MAPPED | TEE_SHM_DMA_BUF;
	char *mem_ref;

	// Find device with equal dev number.
	list_for_each_entry (device, &split_devices, list) {
		if (device->dev == dev) {
			found = true;
			break;
		}
	}

	if (!found) {
		return -EINVAL;
	}

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = WRITE_CHARS;
	inv_arg.session = device->sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	mem = tee_shm_alloc(contr_data.ctx, count, flags);
	if (IS_ERR(mem)) {
		pr_err("Failed to map shared memory: %lx\n", PTR_ERR(mem));
		return PTR_ERR(mem);
	}

	mem_ref = tee_shm_get_va(mem, 0);
	if (IS_ERR(mem_ref)) {
		pr_err("tee_shm_get_va failed: %lx\n", PTR_ERR(mem_ref));
		return PTR_ERR(mem_ref);
	}
	memcpy(mem_ref, buf, count);

	param[0].u.memref.shm = mem;
	param[0].u.memref.size = count;
	param[0].u.memref.shm_offs = 0;
	ret = tee_client_invoke_func(contr_data.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("WRITE_CHARS invoke error: %x from %x.\n", inv_arg.ret,
		       inv_arg.ret_origin);
		return -EINVAL;
	}

	tee_shm_free(mem);

	return 0;
}
EXPORT_SYMBOL(write_optee);
