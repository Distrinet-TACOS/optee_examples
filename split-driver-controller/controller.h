#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/module.h>

#ifndef SPLIT_CONTROLLER
#define SPLIT_CONTROLLER

/**
 * register_split_driver() - Register a driver with this controller.
 * @dev: The device identifier, gotten from the linux kernel during
 * 	 allocation of the driver numbers.
 * @name: A human-readable name for the driver.
 * @update: A callback function to indicate updated data is available.
 * 
 * Return:
 * * 0		- OK
 * * -EINVAL	- Already registered dev identifier
 */
int register_split_driver(dev_t dev, const char *name, void (*update)(dev_t dev));

/**
 * unregister_split_driver() - Unregister a driver with this controller.
 * @dev: The device identifier, gotten from the linux kernel during
 * 	 allocation of the driver numbers.
 * 
 * Return:
 * * 0		- OK
 * * -EINVAL	- Unknown dev identifier
 */
int unregister_split_driver(dev_t dev);

/**
 * open_optee_session() - Open a session to the OPTEE-OS.
 * @dev: The device identifier, gotten from the linux kernel during
 * 	 allocation of the driver numbers.
 * 
 * Return:
 * * 0		- OK
 * * -EINVAL	- Unknown dev identifier
 * * Otherwise error value of open session function
 */
int open_optee_session(dev_t dev);

/**
 * close_optee_session() - Close a session to the OPTEE-OS.
 * @dev: The device identifier, gotten from the linux kernel during
 * 	 allocation of the driver numbers.
 * 
 * Return:
 * * 0		- OK
 * * -EINVAL	- Unknown dev identifier
 * * Otherwise error value of close session function
 */
int close_optee_session(dev_t dev);

/**
 * read_optee() - Read data from the buffer.
 * @dev: The device identifier, gotten from the linux kernel during
 * 	 allocation of the driver numbers.
 * @buf: Output parameter which contains the address of a pointer to a buffer
 *       with the updated characters.
 * @count: Output parameter which contains the amount of characters in the buffer.
 * 
 * Return:
 * * 0		- OK
 * * -EINVAL	- No session exists
 */
int read_optee(dev_t dev, char **buf, size_t *count);

/**
 * write_optee() - Write data from the buffer.
 * @dev: The device identifier, gotten from the linux kernel during
 * 	 allocation of the driver numbers.
 * @buf: The buffer to copy the data from.
 * @count: The amount of characters to copy from the buffer.
 * 
 * Return:
 * * 0		- OK
 * * -EINVAL	- No session exists
 */
int write_optee(dev_t dev, const char *buf, size_t count);

#endif /* SPLIT_CONTROLLER */