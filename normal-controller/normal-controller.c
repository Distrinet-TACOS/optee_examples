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

#include "normal-controller.h"
#include <secure_controller_public.h>

#define DRIVER_NAME "Normal controller"

static const uuid_t sec_cont_uuid =
	UUID_INIT(UUID1, UUID2, UUID3, UUID4, UUID5, UUID6, UUID7, UUID8, UUID9,
		  UUID10, UUID11);

static struct controller {
	u32 sess_id;
	struct tee_context *ctx;
} norm_cont;

struct app {
	uuid_t uuid;
	// Update the device buffers with the new information.
	// For this version, only use a character array (as the devices are
	// character devices).
	void (*notif_handler)(void);

	struct list_head list;
};
LIST_HEAD(apps);

static void print_uuid(uuid_t uuid)
{
	pr_info("%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x\n", uuid.b[0], uuid.b[1],
		uuid.b[2], uuid.b[3], uuid.b[4], uuid.b[5], uuid.b[6],
		uuid.b[7], uuid.b[8], uuid.b[9], uuid.b[10], uuid.b[11],
		uuid.b[12], uuid.b[13], uuid.b[14], uuid.b[15]);
}

static int notify_apps(uuid_t *uuids, unsigned int count)
{
	struct app *app;
	int i;

	list_for_each_entry (app, &apps, list) {
		for (i = 0; i < ALLOCATED_UUIDS; i++) {
			if (uuid_equal(&uuids[i], &app->uuid)) {
				app->notif_handler();
			}
		}
	}

	return 0;
}

static int notification_handler(void)
{
	int ret = 0;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];
	struct tee_shm *mem;
	uuid_t *uuids;
	size_t mem_size = sizeof(__u8) * UUID_SIZE * ALLOCATED_UUIDS;
	u32 flags = TEE_SHM_MAPPED | TEE_SHM_DMA_BUF;

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = GET_NOTIFYING_UUID;
	inv_arg.session = norm_cont.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;

	mem = tee_shm_alloc(norm_cont.ctx, mem_size, flags);
	if (IS_ERR(mem)) {
		pr_err("Failed to map shared memory: %lx\n", PTR_ERR(mem));
		return PTR_ERR(mem);
	}

	uuids = tee_shm_get_va(mem, 0);
	if (IS_ERR(uuids)) {
		pr_err("tee_shm_get_va failed: %lx\n", PTR_ERR(uuids));
		return PTR_ERR(uuids);
	}

	param[0].u.memref.shm = mem;
	param[0].u.memref.size = mem_size;
	param[0].u.memref.shm_offs = 0;

	do {
		ret = tee_client_invoke_func(norm_cont.ctx, &inv_arg, param);
		if ((ret < 0) || (inv_arg.ret != 0)) {
			pr_err("GET_NOTIFYING_UUID invoke error: %x.\n",
			       inv_arg.ret);
			return -EINVAL;
		}
		notify_apps(uuids, param[1].u.value.a);
	} while (param[1].u.value.b); // Not all uuids are retreived.

	tee_shm_free(mem);

	return 0;
}

static int open_session(const char *name, u32 *sess_id)
{
	struct tee_ioctl_open_session_arg sess_arg;
	struct tee_param param[4];
	int ret;

	memset(&sess_arg, 0, sizeof(sess_arg));
	export_uuid(sess_arg.uuid, &sec_cont_uuid);
	sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	sess_arg.num_params = 4;

	memset(&param, 0, sizeof(param));

	ret = tee_client_open_session(norm_cont.ctx, &sess_arg, param);
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
	tee_client_close_session(norm_cont.ctx, sess_id);
	return 0;
}

static int register_notif_callback(void)
{
	int ret;
	struct tee_ioctl_invoke_arg inv_arg;
	struct tee_param param[4];

	memset(&inv_arg, 0, sizeof(inv_arg));
	memset(&param, 0, sizeof(param));

	inv_arg.func = GET_NOTIF_VALUE;
	inv_arg.session = norm_cont.sess_id;
	inv_arg.num_params = 4;

	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;

	ret = tee_client_invoke_func(norm_cont.ctx, &inv_arg, param);
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

static int optee_ctx_match(struct tee_ioctl_version_data *ver, const void *data)
{
	if (ver->impl_id == TEE_IMPL_ID_OPTEE)
		return 1;
	else
		return 0;
}

static int create_context(void)
{
	norm_cont.ctx =
		tee_client_open_context(NULL, optee_ctx_match, NULL, NULL);
	if (IS_ERR(norm_cont.ctx))
		return -ENODEV;

	return 0;
}

static int destroy_context(void)
{
	tee_client_close_context(norm_cont.ctx);

	return 0;
}

static int __init controller_init(void)
{
	create_context();
	open_session(DRIVER_NAME, &norm_cont.sess_id);
	register_notif_callback();

	return 0;
}

static void __exit controller_exit(void)
{
	unregister_callback();
	close_session(norm_cont.sess_id);
	destroy_context();
}

module_init(controller_init);
module_exit(controller_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Tom Van Eyck");

/*************
 *    API    *
 *************/

int nsp_register(uuid_t uuid, void (*notif_handler)(void))
{
	struct app *app;

	list_for_each_entry (app, &apps, list) {
		if (uuid_equal(&uuid, &app->uuid)) {
			return -EINVAL;
		}
	}

	app = kcalloc(1, sizeof(struct app), GFP_KERNEL);
	app->notif_handler = notif_handler;
	app->uuid = uuid;

	list_add(&app->list, &apps);

	return 0;
}
EXPORT_SYMBOL(nsp_register);
