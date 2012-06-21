#ifndef _ASM_X86_FB_H
#define _ASM_X86_FB_H

#include <linux/fb.h>
#include <linux/fs.h>
#include <asm/page.h>

static inline void fb_pgprotect(struct file *file, struct vm_area_struct *vma,
				unsigned long off)
{
}

static int fb_is_primary_device(struct fb_info *info)
{
	return	0;
}

#endif /* _ASM_X86_FB_H */
