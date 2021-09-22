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

enum command { READ_CHAR, REGISTER_ITR, UNREGISTER_ITR };

static struct split_dev {
	struct tee_context *ctx;
	u32 sess_id;
} dev_data;

DEFINE_KFIFO(buffer, char, 256);

static void print_buffer(void)
{
	int res;

	char *output =
		kmalloc(kfifo_len(&buffer) * sizeof(char) + 1, GFP_ATOMIC);
	output[kfifo_len(&buffer)] = '\0';
	res = kfifo_out(&buffer, output, kfifo_len(&buffer));
	pr_info("%s\n", output);
	kfree(output);
}

static irqreturn_t notif_irq_handler(int irq, void *dev_id)
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
	if (input == 13) {
		print_buffer();
		return IRQ_HANDLED;
	} else if (kfifo_is_full(&buffer)) {
		print_buffer();
	}

	kfifo_put(&buffer, input);

	return IRQ_HANDLED;
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

	pr_info("Interrupt registered.\n");
	pr_info("Notification value: %llx.\n", inv_arg.params[0].a);

	ret = request_threaded_irq(64, notif_irq_handler, NULL, 0,
				   "optee_notification", NULL);
	if (ret) {
		pr_alert("Error requesting irq: %i\n", ret);
	} else {
		pr_info("IRQ thread registered successfully.\n");
	}

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

	pr_info("Interrupt unregistered.\n");

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

	pr_alert("Opening session.\n");
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

static int __init hello_init(void)
{
	pr_info("Hello, world\n");
	create_session();
	enableInterrupt();

	return 0;
}

static void __exit hello_exit(void)
{
	pr_info("Goodbye, cruel world\n");
	disableInterrupt();
	destroy_context();
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Tom Van Eyck");
