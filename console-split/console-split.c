#include <linux/init.h>
#include <linux/kfifo.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <controller.h>

#define DRIVER_NAME "Normal world split driver"

static struct split_dev {
	dev_t devt;
	struct cdev cdev;
	struct tee_context *ctx;
	u32 sess_id;
	u32 irq_line;
} dev_data;

#define BUFFER_SIZE 256
DEFINE_KFIFO(buffer, char, BUFFER_SIZE);

static int update(void)
{
	char *buf;
	size_t count;
	int ret;
	size_t chars_copied;

	ret = read_optee(dev_data.devt, buf, &count);
	if (ret < 0) {
		pr_err("Error reading from controller: %x", ret);
		return ret;
	}

	chars_copied = kfifo_in(&buffer, buf, count);
	if (chars_copied < count) {
		pr_alert("Buffer full for driver %s: %x, %x", DRIVER_NAME,
			 MAJOR(dev_data.devt), MINOR(dev_data.devt));
	}

	kfree(buf);
	return 0;
}

static int device_open(struct inode *inode, struct file *filp)
{
	open_optee_session(dev_data.devt);
	return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
	close_optee_session(dev_data.devt);
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
	size_t bytes_left;
	char *buffer = kmalloc(count * sizeof(char), GFP_KERNEL);

	bytes_left = copy_from_user(buffer, buf, count);
	if (bytes_left > 0) {
		pr_err("Not all bytes could be moved from user space buffer. Bytes left: %zu\n",
		       bytes_left);
		return -EFAULT;
	}

	write_optee(dev_data.devt, &buffer, count);

	kfree(buffer);
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

	register_split_driver(dev_data.devt, "console-split", update);

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
	cdev_del(&dev_data.cdev);
	unregister_chrdev_region(dev_data.devt, 1);

	unregister_split_driver(dev_data.devt);

	return 0;
}

static int __init init(void)
{
	register_device();

	return 0;
}

static void __exit exit(void)
{
	unregister_device();
}

module_init(init);
module_exit(exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Tom Van Eyck");
