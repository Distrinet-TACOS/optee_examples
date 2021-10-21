#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/module.h>

#ifndef NORMAL_CONTROLLER
#define NORMAL_CONTROLLER

int nsp_register(uuid_t uuid, void (*notif_handler)(void));

#endif /* NORMAL_CONTROLLER */