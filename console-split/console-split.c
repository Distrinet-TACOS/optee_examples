#include <linux/init.h>
#include <linux/kfifo.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <controller.h>

#define DRIVER_NAME "Normal world split driver"
#define BUFFER_SIZE 256

static unsigned int major;

static struct split_dev {
	dev_t devt;
	struct cdev cdev;
	DECLARE_KFIFO(buffer, char, BUFFER_SIZE);
} * devices;

static void update(dev_t devt)
{
	char *buf;
	size_t count;
	int ret;
	size_t chars_copied;
	char t[256];

	struct split_dev *dev = &devices[MINOR(devt)];

	ret = read_optee(dev->devt, &buf, &count);
	if (ret < 0) {
		pr_err("Error reading from controller: %x", ret);
		kfree(&buf);
		return;
	}

	chars_copied = kfifo_in(&dev->buffer, buf, count);
	if (chars_copied < count) {
		pr_alert("Buffer full for driver %s: %x, %x", DRIVER_NAME,
			 MAJOR(dev->devt), MINOR(dev->devt));
	}

	kfree(buf);
}

static int device_open(struct inode *inode, struct file *filp)
{
	struct split_dev *dev;

	dev = container_of(inode->i_cdev, struct split_dev, cdev);
	filp->private_data = dev;

	return 0;
}

static int device_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int device_read(struct file *filp, char __user *buf, size_t count,
		       loff_t *offp)
{
	int ret;
	size_t bytes_copied;

	struct split_dev *dev = filp->private_data;

	count = min(count, kfifo_len(&dev->buffer));

	ret = kfifo_to_user(&dev->buffer, buf, count, &bytes_copied);
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

	struct split_dev *dev = filp->private_data;

	bytes_left = copy_from_user(buffer, buf, count);
	if (bytes_left > 0) {
		pr_err("Not all bytes could be moved from user space buffer. Bytes left: %zu\n",
		       bytes_left);
		return -EFAULT;
	}

	write_optee(dev->devt, buffer, count);

	kfree(buffer);
	return count;
}

static const struct file_operations fops = { .owner = THIS_MODULE,
					     .open = device_open,
					     .release = device_release,
					     .read = device_read,
					     .write = device_write };

static int register_device(void)
{
	int ret;
	struct class *dev_class;
	u32 devt;

	ret = alloc_chrdev_region(&devt, 0, 2, "console-split");
	if (ret < 0) {
		pr_err("Allocating device number failed with error: %x\n", ret);
		return ret;
	}
	major = MAJOR(devt);

	devices = kmalloc(2 * sizeof(struct split_dev), GFP_KERNEL);
	memset(devices, 0, 2 * sizeof(struct split_dev));
	devices[0].devt = MKDEV(major, 0);
	devices[1].devt = MKDEV(major, 1);
	INIT_KFIFO(devices[0].buffer);
	INIT_KFIFO(devices[1].buffer);

	register_split_driver(devices[0].devt, "console-split", update);
	register_split_driver(devices[1].devt, "console-split-2", update);
	open_optee_session(devices[0].devt);
	open_optee_session(devices[1].devt);

	cdev_init(&devices[0].cdev, &fops);
	devices[0].cdev.owner = THIS_MODULE;
	cdev_init(&devices[1].cdev, &fops);
	devices[1].cdev.owner = THIS_MODULE;

	ret = cdev_add(&devices[0].cdev, devices[0].devt, 1);
	ret += cdev_add(&devices[1].cdev, devices[1].devt, 1);
	if (ret < 0) {
		pr_err("Adding device number failed with error: %x or %x\n",
		       ret, ret / 2);
		return ret;
	}

	dev_class = class_create(THIS_MODULE, "split-driver");
	device_create(dev_class, NULL, devices[0].devt, NULL, "console-split");
	device_create(dev_class, NULL, devices[1].devt, NULL,
		      "console-split-2");

	return 0;
}

static int unregister_device(void)
{
	cdev_del(&devices[0].cdev);
	cdev_del(&devices[1].cdev);
	unregister_chrdev_region(MKDEV(major, 0), 2);

	close_optee_session(devices[0].devt);
	close_optee_session(devices[1].devt);
	unregister_split_driver(devices[0].devt);
	unregister_split_driver(devices[1].devt);

	return 0;
}

static int __init mod_init(void)
{
	register_device();

	return 0;
}

static void __exit mod_exit(void)
{
	unregister_device();
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Tom Van Eyck");
