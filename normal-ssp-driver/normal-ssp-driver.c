#include <linux/init.h>
#include <linux/kfifo.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>

#include "normal-controller.h"
#include <secure_ssp_driver_public.h>

#define DRIVER_NAME "Normal world SSP driver"
#define DEVICE_NAME "normal-ssp-driver"

static const uuid_t sec_ssp_uuid =
	UUID_INIT(UUID1, UUID2, UUID3, UUID4, UUID5, UUID6, UUID7, UUID8, UUID9,
		  UUID10, UUID11);

static struct normal_ssp_driver {
	dev_t devt;
	u32 sess_id;
	struct tee_context *ctx;
	struct cdev cdev;
	DECLARE_KFIFO(buffer, char, BUFFER_SIZE);
} norm_driver;

static void notif_handler(void)
{
	int ret;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];
	struct tee_shm *mem;
	char *buffer;
	size_t mem_size = BUFFER_SIZE * sizeof(char);
	u32 flags = TEE_SHM_MAPPED | TEE_SHM_DMA_BUF;
	size_t chars_copied;
	size_t count;

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = UPDATE_BUFFER;
	inv_arg.session = norm_driver.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;

	mem = tee_shm_alloc(norm_driver.ctx, mem_size, flags);
	if (IS_ERR(mem)) {
		pr_err("Failed to map shared memory: %lx\n", PTR_ERR(mem));
		return;
	}

	buffer = tee_shm_get_va(mem, 0);
	if (IS_ERR(buffer)) {
		pr_err("tee_shm_get_va failed: %lx\n", PTR_ERR(buffer));
		return;
	}

	param[0].u.memref.shm = mem;
	param[0].u.memref.size = mem_size;
	param[0].u.memref.shm_offs = 0;

	ret = tee_client_invoke_func(norm_driver.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("UPDATE_BUFFER invoke error: %x.\n", inv_arg.ret);
		return;
	}

	count = param[0].u.memref.size / sizeof(char);
	chars_copied = kfifo_in(&norm_driver.buffer, buffer, count);
	if (chars_copied < count) {
		pr_alert("Buffer full for driver %s: %x, %x", DRIVER_NAME,
			 MAJOR(norm_driver.devt), MINOR(norm_driver.devt));
	}

	tee_shm_free(mem);
}

static int device_read(struct file *filp __always_unused, char __user *buf,
		       size_t count, loff_t *offp)
{
	int ret;
	size_t bytes_copied;

	count = min(count, kfifo_len(&norm_driver.buffer));

	ret = kfifo_to_user(&norm_driver.buffer, buf, count, &bytes_copied);
	if (ret < 0) {
		pr_err("User space buffer not large enough for requested count. Bytes copied: %zu, count: %zu\n",
		       bytes_copied, count);
		return -EFAULT;
	}

	return bytes_copied;
}

int write_optee(const char *buf, size_t count)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];
	struct tee_shm *mem;
	u32 flags = TEE_SHM_MAPPED | TEE_SHM_DMA_BUF;
	char *mem_ref;

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = WRITE_CHARS;
	inv_arg.session = norm_driver.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	mem = tee_shm_alloc(norm_driver.ctx, count, flags);
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
	ret = tee_client_invoke_func(norm_driver.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("WRITE_CHARS invoke error: %x from %x.\n", inv_arg.ret,
		       inv_arg.ret_origin);
		return -EINVAL;
	}

	tee_shm_free(mem);

	return 0;
}

static int device_write(struct file *filp __always_unused,
			const char __user *buf, size_t count, loff_t *offp)
{
	size_t bytes_left;
	char *buffer = kmalloc(count * sizeof(char), GFP_KERNEL);

	bytes_left = copy_from_user(buffer, buf, count);
	if (bytes_left > 0) {
		pr_err("Not all bytes could be moved from user space buffer. Bytes left: %zu\n",
		       bytes_left);
		return -EFAULT;
	}

	write_optee(buffer, count);

	kfree(buffer);
	return count;
}

static const struct file_operations fops = { .owner = THIS_MODULE,
					     .read = device_read,
					     .write = device_write };

static int register_device(void)
{
	int ret;
	struct class *dev_class;

	ret = alloc_chrdev_region(&norm_driver.devt, 0, 1, DEVICE_NAME);
	if (ret < 0) {
		pr_err("Allocating device number failed with error: %x\n", ret);
		return ret;
	}
	INIT_KFIFO(norm_driver.buffer);

	cdev_init(&norm_driver.cdev, &fops);
	norm_driver.cdev.owner = THIS_MODULE;

	ret = cdev_add(&norm_driver.cdev, norm_driver.devt, 1);
	if (ret < 0) {
		pr_err("Adding device number failed with error: %x or %x\n",
		       ret, ret / 2);
		return ret;
	}

	dev_class = class_create(THIS_MODULE, DEVICE_NAME "-class");
	device_create(dev_class, NULL, norm_driver.devt, NULL, DEVICE_NAME);

	return 0;
}

static int unregister_device(void)
{
	cdev_del(&norm_driver.cdev);
	unregister_chrdev_region(norm_driver.devt, 1);

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

	ret = tee_client_invoke_func(norm_driver.ctx, &inv_arg, param);
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

	ret = tee_client_invoke_func(norm_driver.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("UNREGISTER_ITR invoke error: %x.\n", inv_arg.ret);
		return -EINVAL;
	}

	return 0;
}

static int open_session(const char *name, u32 *sess_id)
{
	struct tee_ioctl_open_session_arg sess_arg;
	struct tee_param param[4];
	int ret;

	memset(&sess_arg, 0, sizeof(sess_arg));
	export_uuid(sess_arg.uuid, &sec_ssp_uuid);
	sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	sess_arg.num_params = 4;

	memset(&param, 0, sizeof(param));

	ret = tee_client_open_session(norm_driver.ctx, &sess_arg, param);
	if ((ret < 0) || (sess_arg.ret != 0)) {
		pr_err("tee_client_open_session failed for device %s, err: %x\n",
		       name, sess_arg.ret);
		return -EINVAL;
	}
	*sess_id = sess_arg.session;

	return 0;
}

static void close_session(void)
{
	tee_client_close_session(norm_driver.ctx, norm_driver.sess_id);
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
	norm_driver.ctx =
		tee_client_open_context(NULL, optee_ctx_match, NULL, NULL);
	if (IS_ERR(norm_driver.ctx))
		return -ENODEV;

	return 0;
}

static void destroy_context(void)
{
	tee_client_close_context(norm_driver.ctx);
}

static int __init mod_init(void)
{
	create_context();
	open_session(DRIVER_NAME, &norm_driver.sess_id);
	nsp_register(sec_ssp_uuid, notif_handler);
	enable_interrupt(norm_driver.sess_id);
	register_device();

	return 0;
}

static void __exit mod_exit(void)
{
	unregister_device();
	disable_interrupt(norm_driver.sess_id);

	destroy_context();
	close_session();
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Tom Van Eyck");
