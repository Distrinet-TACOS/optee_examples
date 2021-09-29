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

#define DRIVER_NAME "Normal world split driver"

static const uuid_t pta_id = UUID_INIT(0x661b512b, 0x53a3, 0x4cec, 0xa8, 0xfe,
				       0x48, 0x0c, 0x8a, 0x74, 0x05, 0xfe);

enum command { READ_CHAR, REGISTER_ITR, UNREGISTER_ITR, WRITE_CHARS };

static struct split_dev {
	dev_t devt;
	struct cdev cdev;
	struct tee_context *ctx;
	u32 sess_id;
	u32 irq_line;
} dev_data;

#define BUFFER_SIZE 256
DEFINE_KFIFO(buffer, char, BUFFER_SIZE);

static int notif_irq_handler(void)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];
	char input;

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = READ_CHAR;
	inv_arg.session = dev_data.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	ret = tee_client_invoke_func(dev_data.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("READ_CHAR invoke error: %x.\n", inv_arg.ret);
		return -EINVAL;
	}

	input = (char)inv_arg.params[0].a;
	kfifo_put(&buffer, input);

	return 0;
}

static int enableInterrupt(void)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = REGISTER_ITR;
	inv_arg.session = dev_data.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	ret = tee_client_invoke_func(dev_data.ctx, &inv_arg, param);
	if ((ret < 0) || (inv_arg.ret != 0)) {
		pr_err("REGISTER_ITR invoke error: %x.\n", inv_arg.ret);
		return -EINVAL;
	}

	register_callback(notif_irq_handler, inv_arg.params[0].a);

	return 0;
}

static int disableInterrupt(void)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = UNREGISTER_ITR;
	inv_arg.session = dev_data.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	param[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	ret = tee_client_invoke_func(dev_data.ctx, &inv_arg, param);
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

static int create_session(void)
{
	int ret = 0;
	int err = -ENODEV;
	struct tee_ioctl_open_session_arg sess_arg;

	memset(&sess_arg, 0, sizeof(sess_arg));

	dev_data.ctx =
		tee_client_open_context(NULL, optee_ctx_match, NULL, NULL);
	if (IS_ERR(dev_data.ctx))
		return -ENODEV;

	export_uuid(sess_arg.uuid, &pta_id);
	sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	sess_arg.num_params = 0;

	ret = tee_client_open_session(dev_data.ctx, &sess_arg, NULL);
	if ((ret < 0) || (sess_arg.ret != 0)) {
		pr_err("tee_client_open_session failed, err: %x\n",
		       sess_arg.ret);
		err = -EINVAL;
		tee_client_close_context(dev_data.ctx);
		return err;
	}
	dev_data.sess_id = sess_arg.session;

	return 0;
}

static int destroy_context(void)
{
	tee_client_close_session(dev_data.ctx, dev_data.sess_id);
	tee_client_close_context(dev_data.ctx);

	return 0;
}

static int device_open(struct inode *inode, struct file *filp)
{
	// create_session();
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
	ret = alloc_chrdev_region(&dev_data.devt, 0, 1, "console-split");
	if (ret < 0) {
		pr_err("Allocating device number failed with error: %x\n", ret);
		return ret;
	}

	cdev_init(&dev_data.cdev, &fops);
	dev_data.cdev.owner = THIS_MODULE;

	ret = cdev_add(&dev_data.cdev, dev_data.devt, 1);
	if (ret < 0) {
		pr_err("Adding device number failed with error: %x\n", ret);
		return ret;
	}

	return 0;
}

static int unregister_device(void)
{
	unregister_chrdev_region(dev_data.devt, 1);
	cdev_del(&dev_data.cdev);

	return 0;
}

static int __init hello_init(void)
{
	create_session();
	enableInterrupt();

	register_device();

	return 0;
}

static void __exit hello_exit(void)
{
	unregister_device();

	disableInterrupt();
	destroy_context();
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Tom Van Eyck");
