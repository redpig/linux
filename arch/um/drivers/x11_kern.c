#include <linux/init.h>
#include <generated/autoconf.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/fb.h>
#include <linux/input.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/console.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/platform_device.h>

#include "irq_kern.h"
#include "irq_user.h"
#include "x11_kern.h"
#include "x11_user.h"

#define DRIVER_NAME "uml-x11-fb"
/* #define X11_UM_DEBUG 1 */

/* ------------------------------------------------------------------ */

static int x11_enable  = 0;
static int x11_fps     = 60;
static int x11_touch   = 0;
static int x11_mouse_scale = 1;	/* Use xset m 1 for ideal behavior or set scale=2 to leave userland alone */
static int x11_width;
static int x11_height;

struct x11_mapping {
	struct list_head	  entry;
	struct vm_area_struct     *vma;
	atomic_t                  map_refs;
	int                       faults;
	struct x11_kerndata       *kd;
};

struct x11_kerndata;
struct x11_work {
	struct work_struct work; /* Only one work struct is ever needed right now */
	struct x11_kerndata *kd;
};

struct x11_kerndata {
	/* common stuff */
	struct x11_window         *win;
	struct workqueue_struct   *refresh_wq;
	int                       has_data;
	struct x11_work		  work;

	/* framebuffer driver */
	unsigned char             *fb;
	struct fb_fix_screeninfo  *fix;
        struct fb_var_screeninfo  *var;
	struct fb_info            *info;
	struct timer_list         refresh;
	int                       dirty, y1, y2;

	/* fb mapping */
	struct semaphore          mm_lock;
	unsigned long              nr_pages;
	struct page               **pages;
	struct list_head	  mappings;

	/* input drivers */
	struct input_dev          *kbd;
	struct input_dev          *mouse;
	int 			  mouse_x;
	int 			  mouse_y;
	int			  depressed;
};

void x11_update_screen(struct x11_kerndata *kd)
{
	int y1,y2,offset,length;
	unsigned char *src, *dst;
	struct list_head *item;
	struct x11_mapping *map;

	y1 = kd->y1;
	y2 = kd->y2;
	kd->dirty = kd->y1 = kd->y2 = 0;
	down(&kd->mm_lock);
	list_for_each(item, &kd->mappings) {
		map = list_entry(item, struct x11_mapping, entry);
		if (!map->faults)
			continue;
		zap_page_range(map->vma, map->vma->vm_start,
			       map->vma->vm_end - map->vma->vm_start, NULL);
		map->faults = 0;
	}
	up(&kd->mm_lock);

	offset = y1 * kd->fix->line_length;
	length = (y2 - y1) * kd->fix->line_length;
	src = kd->fb + offset;
	dst = x11_get_fbmem(kd->win) + offset;
	memcpy(dst, src, length);
	x11_blit_fb(kd->win, y1, y2);
}

static void x11_thread(struct work_struct *wrk)
{
	struct x11_work *w = container_of(wrk, struct x11_work, work);
	struct x11_kerndata *kd = w->kd;

	/* This can be MUCH more efficient. Just trying to get it cleaned up. */
	if (!kd->dirty && !kd->has_data) {
		printk("x11_thread: not dirty. Bailing\n");
		return;
	}
	if (kd->dirty)
		x11_update_screen(kd);
	if (kd->has_data) {
		kd->has_data = 0;
		x11_has_data(kd->win,kd);
		reactivate_fd(x11_get_fd(kd->win), X11_IRQ);
	}
}

/* ------------------------------------------------------------------ */
/* input driver                                                       */

void x11_kbd_input(struct x11_kerndata *kd, int key, int down)
{
	if (key >= KEY_MAX) {
		if (down)
			printk("%s: unknown key pressed [%d]\n",
			       __FUNCTION__, key-KEY_MAX);
		return;
	}
	input_report_key(kd->kbd,key,down);
	input_sync(kd->kbd);
}

void x11_mouse_input(struct x11_kerndata *kd, int key, int down,
		     int x, int y)
{
	int dx, dy;
#ifdef X11_UM_DEBUG
	printk("mouse_input: key:%d down:%d x:%d y:%d\n", key, down, x, y);
#endif
	if (x11_touch) {
		if (key != KEY_RESERVED) {
			if (down) {
				input_report_abs(kd->mouse, ABS_MT_TOUCH_MAJOR, 255);
				input_report_abs(kd->mouse, ABS_MT_POSITION_X, x);
				input_report_abs(kd->mouse, ABS_MT_POSITION_Y, y);
				input_report_abs(kd->mouse, ABS_PRESSURE, 255);
				/* Map all buttons to touch right now */
				input_report_key(kd->mouse, BTN_TOUCH, 1);
				printk(KERN_INFO "touch @ %d, %d\n", x, y);
				kd->depressed = 1;
			} else {
				input_report_abs(kd->mouse, ABS_MT_TOUCH_MAJOR, 0);
				input_report_abs(kd->mouse, ABS_PRESSURE, 0);
				input_report_key(kd->mouse, BTN_TOUCH, 0);
				printk(KERN_INFO "touch released @ %d, %d\n", x, y);
				kd->depressed = 0;
			}
		} else {
			if (kd->depressed) {
				input_report_abs(kd->mouse, ABS_MT_POSITION_X, x);
				input_report_abs(kd->mouse, ABS_MT_POSITION_Y, y);
				printk(KERN_INFO "touch dragged @ %d, %d\n", x, y);
			}
		}
		input_mt_sync(kd->mouse);
		input_sync(kd->mouse);
		return;
	}
	/* Normal mouse scaled by a boot-time configured scalar. */
	input_report_rel(kd->mouse, REL_X, (x - kd->mouse_x) / x11_mouse_scale);
	input_report_rel(kd->mouse, REL_Y, (y - kd->mouse_y) / x11_mouse_scale);
	kd->mouse_x = x;
	kd->mouse_y = y;
	if (key != KEY_RESERVED)
		input_report_key(kd->mouse, key, down);
	input_sync(kd->mouse);
}

void x11_cad(struct x11_kerndata *kd)
{
	printk("%s\n",__FUNCTION__);
}

/* ------------------------------------------------------------------ */
/* framebuffer driver                                                 */

static int x11_setcolreg(unsigned regno, unsigned red, unsigned green,
			 unsigned blue, unsigned transp,
			 struct fb_info *info)
{
	if (regno >= info->cmap.len)
		return 1;

	switch (info->var.bits_per_pixel) {
	case 16:
		if (info->var.red.offset == 10) {
			/* 1:5:5:5 */
			((u32*) (info->pseudo_palette))[regno] =
				((red   & 0xf800) >>  1) |
				((green & 0xf800) >>  6) |
				((blue  & 0xf800) >> 11);
		} else {
			/* 0:5:6:5 */
			((u32*) (info->pseudo_palette))[regno] =
				((red   & 0xf800)      ) |
				((green & 0xfc00) >>  5) |
				((blue  & 0xf800) >> 11);
		}
		break;
	case 24:
		red   >>= 8;
		green >>= 8;
		blue  >>= 8;
		((u32 *)(info->pseudo_palette))[regno] =
			(red   << info->var.red.offset)   |
			(green << info->var.green.offset) |
			(blue  << info->var.blue.offset);
		break;
	case 32:
		red   >>= 8;
		green >>= 8;
		blue  >>= 8;
		((u32 *)(info->pseudo_palette))[regno] =
			(red   << info->var.red.offset)   |
			(green << info->var.green.offset) |
			(blue  << info->var.blue.offset);
		break;
	}
	return 0;
}

static void x11_fb_timer(unsigned long data)
{
	struct x11_kerndata *kd = (struct x11_kerndata*)data;
	kd->dirty++;
	/* XXX: reuses work. COuld be sad if it overlaps. */
	queue_work(kd->refresh_wq, &kd->work.work);
}

static void x11_fb_refresh(struct x11_kerndata *kd, int y1, int h)
{
	int y2;

	y2 = y1 + h;
	if (0 == kd->y2) {
		kd->y1 = y1;
		kd->y2 = y2;
	}
	if (kd->y1 > y1)
		kd->y1 = y1;
	if (kd->y2 < y2)
		kd->y2 = y2;

	/* XXX: this needed */
	if (timer_pending(&kd->refresh))
		return;
	mod_timer(&kd->refresh, jiffies + HZ/x11_fps);
}

void x11_fillrect(struct fb_info *p, const struct fb_fillrect *rect)
{
	struct x11_kerndata *kd = p->par;

	cfb_fillrect(p, rect);
	down(&kd->mm_lock);
	x11_fb_refresh(kd, rect->dy, rect->height);
	up(&kd->mm_lock);
}

void x11_imageblit(struct fb_info *p, const struct fb_image *image)
{
	struct x11_kerndata *kd = p->par;

	cfb_imageblit(p, image);
	down(&kd->mm_lock);
	x11_fb_refresh(kd, image->dy, image->height);
	up(&kd->mm_lock);
}

void x11_copyarea(struct fb_info *p, const struct fb_copyarea *area)
{
	struct x11_kerndata *kd = p->par;

	cfb_copyarea(p, area);
	x11_fb_refresh(kd, area->dy, area->height);
}

/* ------------------------------------------------------------------ */

static void
x11_fb_vm_open(struct vm_area_struct *vma)
{
	struct x11_mapping *map = vma->vm_private_data;

	atomic_inc(&map->map_refs);
}

static void
x11_fb_vm_close(struct vm_area_struct *vma)
{
	struct x11_mapping *map = vma->vm_private_data;
	struct x11_kerndata *kd = map->kd;

	down(&kd->mm_lock);
	if (atomic_dec_and_test(&map->map_refs)) {
		list_del(&map->entry);
		kfree(map);
	}
	up(&kd->mm_lock);
}

static int
x11_fb_vm_nopage(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct x11_mapping *map = vma->vm_private_data;
	struct x11_kerndata *kd = map->kd;
	/* unsigned long pgnr = (vmf->pgoff - vma->vm_start) >> PAGE_SHIFT; */
	unsigned long pgnr = vmf->pgoff;
	struct page *page;
	int y1,y2;

	if (pgnr >= kd->nr_pages) {
		return VM_FAULT_SIGBUS;
	}

	down(&kd->mm_lock);
	page = kd->pages[pgnr];
	get_page(page);
	map->faults++;

	y1 = (pgnr << PAGE_SHIFT) / kd->fix->line_length;
	y2 = ((pgnr << PAGE_SHIFT) + PAGE_SIZE-1) / kd->fix->line_length;
	if (y2 > kd->var->yres)
		y2 = kd->var->yres;
	x11_fb_refresh(kd, y1, y2 - y1);
	up(&kd->mm_lock);

	vmf->page = page;
	return	0;
}

static struct vm_operations_struct x11_fb_vm_ops =
{
	.open     = x11_fb_vm_open,
	.close    = x11_fb_vm_close,
	.fault    = x11_fb_vm_nopage,
};

int x11_mmap(struct fb_info *p,  struct vm_area_struct * vma)
{
	struct x11_kerndata *kd = p->par;
	struct x11_mapping *map = NULL;
	int retval;
	int map_pages;

	printk("%s\n",__FUNCTION__);
	down(&kd->mm_lock);

	retval = -ENOMEM;
	if (NULL == (map = kzalloc(sizeof(*map), GFP_KERNEL))) {
		printk("%s: oops, out of memory\n",__FUNCTION__);
		goto out;
	}

	retval = -EINVAL;
	if (!(vma->vm_flags & VM_WRITE)) {
		printk("%s: need writable mapping\n",__FUNCTION__);
		goto out;
	}
	if (!(vma->vm_flags & VM_SHARED)) {
		printk("%s: need shared mapping\n",__FUNCTION__);
		goto out;
	}
	if (vma->vm_pgoff != 0) {
		printk("%s: need offset 0 (vm_pgoff=%ld)\n",__FUNCTION__,
		       vma->vm_pgoff);
		goto out;
	}

	map_pages = (vma->vm_end - vma->vm_start + PAGE_SIZE-1) >> PAGE_SHIFT;
	if (map_pages > kd->nr_pages) {
		printk("%s: mapping to big (%ld > %d)\n",__FUNCTION__,
		       vma->vm_end - vma->vm_start, p->fix.smem_len);
		goto out;
	}

	map->vma = vma;
	map->faults = 0;
	map->kd = kd;
	atomic_set(&map->map_refs,1);
	list_add_tail(&map->entry, &kd->mappings);
	vma->vm_ops   = &x11_fb_vm_ops;
	vma->vm_flags |= VM_DONTEXPAND | VM_RESERVED;
	vma->vm_private_data = map;
	retval = 0;
	map = NULL; /* Streamline out flow */

out:
	if (map)
		kfree(map);
	up(&kd->mm_lock);
	return retval;
}

/* ------------------------------------------------------------------ */

static struct fb_ops x11_fb_ops = {
	.owner		= THIS_MODULE,
	.fb_setcolreg	= x11_setcolreg,
	.fb_fillrect	= x11_fillrect,
	.fb_copyarea	= x11_copyarea,
	.fb_imageblit	= x11_imageblit,
	.fb_mmap        = x11_mmap,
};

/* ---------------------------------------------------------------------------- */

static irqreturn_t x11_irq(int irq, void *data)
{
	struct x11_kerndata *kd = data;
#ifdef X11_UM_DEBUG
	printk("x11_irq fired!\n");
#endif
	kd->has_data++;
	queue_work(kd->refresh_wq, &kd->work.work);

	return IRQ_HANDLED;
}

static int __init x11_probe(struct device *device)
{
	struct x11_kerndata *kd;
	int i;
	int err;

	kd = kzalloc(sizeof(*kd),GFP_KERNEL);
	if (NULL == kd)
		return -ENOMEM;

	kd->kbd   = input_allocate_device();
	kd->mouse = input_allocate_device();
	if (NULL == kd->kbd || NULL == kd->mouse)
		goto fail_free;
	/* Not used yet, but would provide kd encapsulation. */
	input_set_drvdata(kd->kbd, kd);
	input_set_drvdata(kd->mouse, kd);

	kd->win = x11_open(x11_width, x11_height);
	if (NULL == kd->win) {
		printk(DRIVER_NAME ": can't open X11 window\n");
		goto fail_free;
	}
	kd->fix = x11_get_fix(kd->win);
	kd->var = x11_get_var(kd->win);
	INIT_LIST_HEAD(&kd->mappings);

	/* alloc memory */
	kd->fb  = vmalloc(kd->fix->smem_len);
	if (NULL == kd->fb) {
		printk("%s: vmalloc(%d) failed\n",
		       __FUNCTION__,kd->fix->smem_len);
		goto fail_close;
	}
	memset(kd->fb,0,kd->fix->smem_len);
	kd->nr_pages  = (kd->fix->smem_len + PAGE_SIZE-1) >> PAGE_SHIFT;
	kd->pages = kmalloc(sizeof(struct page*)*kd->nr_pages, GFP_KERNEL);
	if (NULL == kd->pages)
		goto fail_vfree;
	for (i = 0; i < kd->nr_pages; i++)
		kd->pages[i] = vmalloc_to_page(kd->fb + i*PAGE_SIZE);

	/* framebuffer setup */
	kd->info = framebuffer_alloc(sizeof(u32) * 256, device);
	kd->info->pseudo_palette = kd->info->par;
	kd->info->par = kd;
        kd->info->screen_base = kd->fb;

	kd->info->fbops = &x11_fb_ops;
	kd->info->var = *kd->var;
	kd->info->fix = *kd->fix;
	kd->info->flags = FBINFO_FLAG_DEFAULT;

	fb_alloc_cmap(&kd->info->cmap, 256, 0);
	register_framebuffer(kd->info);
	printk(KERN_INFO "fb%d: %s frame buffer device, %dx%d, %d fps, %d bpp (%d:%d:%d)\n",
	       kd->info->node, kd->info->fix.id,
	       kd->var->xres, kd->var->yres, x11_fps, kd->var->bits_per_pixel,
	       kd->var->red.length, kd->var->green.length, kd->var->blue.length);

	/* keyboard setup */
	set_bit(EV_KEY, kd->kbd->evbit);
	for (i = 0; i < KEY_MAX; i++)
		set_bit(i, kd->kbd->keybit);
	kd->kbd->id.bustype = BUS_HOST;
	kd->kbd->name = DRIVER_NAME "-keyboard";
	kd->kbd->phys = DRIVER_NAME "/input0";
	//kd->kbd->dev = device;
	err = input_register_device(kd->kbd);
	if (err)
		goto fail_vfree;

	/* mouse setup */
	set_bit(EV_KEY,     kd->mouse->evbit);
	set_bit(EV_SYN,     kd->mouse->evbit);
	if (!x11_touch) {
		set_bit(EV_REL,     kd->mouse->evbit);
		set_bit(BTN_LEFT,   kd->mouse->keybit);
		set_bit(BTN_MIDDLE, kd->mouse->keybit);
		set_bit(BTN_RIGHT,  kd->mouse->keybit);
		set_bit(REL_X,      kd->mouse->relbit);
		set_bit(REL_Y,      kd->mouse->relbit);
	} else {
		set_bit(EV_ABS,     kd->mouse->evbit);
		set_bit(ABS_X,      kd->mouse->absbit);
		set_bit(ABS_Y,      kd->mouse->absbit);
		set_bit(ABS_MT_TOUCH_MAJOR, kd->mouse->absbit);
		set_bit(ABS_MT_POSITION_X, kd->mouse->absbit);
		set_bit(ABS_MT_POSITION_Y, kd->mouse->absbit);
		set_bit(ABS_PRESSURE, kd->mouse->absbit);
		set_bit(BTN_TOUCH, kd->mouse->keybit);
		input_set_abs_params(kd->mouse, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);
		input_set_abs_params(kd->mouse, ABS_MT_POSITION_X, 0, kd->var->xres, 0, 0);
		input_set_abs_params(kd->mouse, ABS_MT_POSITION_Y, 0, kd->var->yres, 0, 0);
		input_set_abs_params(kd->mouse, ABS_PRESSURE, 0, 255, 0, 0);
	}
	kd->mouse->id.bustype = BUS_HOST;
	kd->mouse->name = DRIVER_NAME "-mouse";
	kd->mouse->phys = DRIVER_NAME "/input1";
	//kd->mouse->dev = device;
	err = input_register_device(kd->mouse);
	if (err)
		goto fail_vfree;

	kd->refresh_wq = alloc_workqueue("kx11d", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	if (!kd->refresh_wq) {
		err = -ENOMEM;
		goto fail_vfree; /* not quite right. */
	}
	kd->work.kd = kd;
	INIT_WORK(&kd->work.work, x11_thread);

	/* misc common kernel stuff */
	sema_init(&kd->mm_lock, 1);
	init_timer(&kd->refresh);
	kd->refresh.function = x11_fb_timer;
	kd->refresh.data     = (unsigned long)kd;

#ifdef X11_UM_DEBUG
	printk(KERN_INFO "x11 fd: %d\n", x11_get_fd(kd->win));
#endif
	err = um_request_irq(X11_IRQ, x11_get_fd(kd->win), IRQ_READ, x11_irq,
		       IRQF_SHARED, DRIVER_NAME, kd);
	if (err)
		printk(KERN_ERR "x11fb failed to get input IRQ\n");

	return err;

fail_vfree:
	vfree(kd->fb);
fail_close:
	x11_close(kd->win);
fail_free:
	if (kd->kbd)
		input_free_device(kd->kbd);
	if (kd->mouse)
		input_free_device(kd->mouse);
	kfree(kd);
	return -ENODEV;
}

static struct device_driver x11_driver = {
	.name  = DRIVER_NAME,
	.bus   = &platform_bus_type,
	.probe = x11_probe,
};
static struct platform_device x11_device = {
	.name  = DRIVER_NAME,
};

static int __init x11_init(void)
{
	int ret;
	printk("%s\n",__FUNCTION__);

	ret = driver_register(&x11_driver);
	printk("%s driver_register=%d\n",__FUNCTION__,ret);
	if (ret)
		return ret;
	printk("%s x11_enable=%d\n",__FUNCTION__,x11_enable);
	if (!x11_enable)
		return 0;
	ret = platform_device_register(&x11_device);
	printk("%s platform_device_register=%d\n",__FUNCTION__,ret);
	if (ret)
		driver_unregister(&x11_driver);
	return ret;
}

static void __exit x11_fini(void)
{
	if (x11_enable)
		platform_device_unregister(&x11_device);
	driver_unregister(&x11_driver);
}

module_init(x11_init);
module_exit(x11_fini);

static int x11_setup(char *str)
{
	printk("%s: x11=%s\n",__FUNCTION__,str);
	if (3 == sscanf(str,"%dx%d@%d",&x11_width,&x11_height,&x11_fps) ||
	    2 == sscanf(str,"%dx%d",&x11_width,&x11_height)) {
		//printk("%s: enable linux vt subsystem\n",__FUNCTION__);
		x11_enable = 1;
#if defined(CONFIG_DUMMY_CONSOLE)
		conswitchp = &dummy_con;
#endif
		return 0;
	}
	return -1;
}
__setup("x11=", x11_setup);

static int x11_input(char *str)
{
	printk("%s: x11_input=%s\n",__FUNCTION__,str);
	char *match;
	if (strstr(str, "touch:1")) {
		x11_touch = 1;
		printk(KERN_INFO "uml-x11-fb: simulating touch events\n");
	}
	match = strstr(str, "scale:");
	if (match) {
		if (1 != sscanf(match, "scale:%d", &x11_mouse_scale) || x11_mouse_scale == 0)
			x11_mouse_scale = 1;
		printk(KERN_INFO "uml-x11-fb: mouse scale = %d\n", x11_mouse_scale);
	}

	return 0;
}
__setup("x11_input=", x11_input);
/*
 * Local variables:
 * c-basic-offset: 8
 * End:
 */
