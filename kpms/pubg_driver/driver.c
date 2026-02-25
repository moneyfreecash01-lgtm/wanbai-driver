/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * wanbai – KPatch-Next KPM kernel driver
 *
 * ioctl interface matching wanbai.h:
 *   OP_INIT_KEY    (0x800)
 *   OP_READ_MEM    (0x801)
 *   OP_WRITE_MEM   (0x802)
 *   OP_MODULE_BASE (0x803)
 *
 * Uses manual typedefs (not kfunc_def) and manual struct layouts to avoid
 * KPatch-Next stripped-header limitations.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>     /* compat_copy_to_user, compat_strncpy_from_user */
#include <ktypes.h>
#include <linux/printk.h>

KPM_NAME("wanbai");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("pubg-cheat");
KPM_DESCRIPTION("Kernel memory driver for PUBG overlay cheat (/dev/wanbai)");

#define OP_INIT_KEY     0x800
#define OP_READ_MEM     0x801
#define OP_WRITE_MEM    0x802
#define OP_MODULE_BASE  0x803

typedef struct {
    int32_t   pid;
    uint64_t  addr;
    uint64_t  buffer;
    uint64_t  size;
} __attribute__((packed)) COPY_MEMORY;

typedef struct {
    int32_t   pid;
    uint64_t  name;
    uint64_t  base;
} __attribute__((packed)) MODULE_BASE;

/* Opaque types */
struct task_struct;
struct pid;
struct mm_struct;
struct vm_area_struct;
struct iovec;
struct path;
struct file;
struct module;
struct device;

#define GFP_KERNEL  0xcc0u
#define GFP_ATOMIC  0x200u
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define PIDTYPE_PID 0
#define MISC_DYNAMIC_MINOR 255

/* -----------------------------------------------------------------------
 * file_operations ABI layout for arm64 Linux 4.x–6.x
 * Only defining fields up to and including compat_ioctl.
 * Zero-initialized globals are safe for fields we don't use.
 * --------------------------------------------------------------------- */
struct kpm_file_operations {
    struct module    *owner;           /* 0x00 */
    void             *llseek;          /* 0x08 */
    void             *read;            /* 0x10 */
    void             *write;           /* 0x18 */
    void             *read_iter;       /* 0x20 */
    void             *write_iter;      /* 0x28 */
    void             *iopoll;          /* 0x30 – added in 5.1, zero if absent */
    void             *iterate;         /* 0x38 */
    void             *iterate_shared;  /* 0x40 */
    void             *poll;            /* 0x48 */
    long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long); /* 0x50 */
    long (*compat_ioctl)(struct file *, unsigned int, unsigned long);   /* 0x58 */
    /* remaining fields zero = no-op */
    void             *mmap;            /* 0x60 */
    void             *mmap_supported_flags; /* 0x68 */
    void             *open;           /* 0x70 */
    void             *flush;          /* 0x78 */
    void             *release;        /* 0x80 */
};

/* miscdevice ABI layout for arm64 Linux 4.x–6.x */
struct kpm_miscdevice {
    int                          minor;
    const char                  *name;
    const struct kpm_file_operations *fops;
    struct { void *next; void *prev; } list;  /* list_head */
    struct device               *parent;
    struct device               *this_device;
    const void                  *groups;       /* attribute_group**, 5.x+ */
    const char                  *nodename;
    unsigned int                 mode;
};

/* -----------------------------------------------------------------------
 * Kernel function pointer typedefs
 * --------------------------------------------------------------------- */
typedef struct pid           *(*t_find_get_pid)(int32_t);
typedef struct task_struct   *(*t_get_pid_task)(struct pid *, int);
typedef void                  (*t_put_pid)(struct pid *);
typedef void                  (*t_put_task_struct)(struct task_struct *);
typedef struct mm_struct     *(*t_get_task_mm)(struct task_struct *);
typedef void                  (*t_mmput)(struct mm_struct *);
typedef ssize_t               (*t_process_vm_rw)(struct task_struct *,
                                                  const struct iovec *, uint64_t,
                                                  const struct iovec *, uint64_t,
                                                  uint64_t, int);
typedef int                   (*t_misc_register)(struct kpm_miscdevice *);
typedef void                  (*t_misc_deregister)(struct kpm_miscdevice *);
typedef void                 *(*t_kmalloc)(uint64_t, uint32_t);
typedef void                  (*t_kfree)(const void *);
typedef uint64_t              (*t_get_zeroed_page)(uint32_t);
typedef void                  (*t_free_pages)(uint64_t, uint32_t);
typedef char                 *(*t_d_path)(const struct path *, char *, int);
typedef int                   (*t_down_read)(void *);
typedef void                  (*t_up_read)(void *);
typedef long                  (*t_copy_from_user)(void *, const void *, uint64_t);

static t_find_get_pid     kp_find_get_pid;
static t_get_pid_task     kp_get_pid_task;
static t_put_pid          kp_put_pid;
static t_put_task_struct  kp_put_task_struct;
static t_get_task_mm      kp_get_task_mm;
static t_mmput            kp_mmput;
static t_process_vm_rw    kp_process_vm_rw;
static t_misc_register    kp_misc_register;
static t_misc_deregister  kp_misc_deregister;
static t_kmalloc          kp_kmalloc;
static t_kfree            kp_kfree;
static t_get_zeroed_page  kp_get_zeroed_page;
static t_free_pages       kp_free_pages;
static t_d_path           kp_d_path;
static t_down_read        kp_down_read;
static t_up_read          kp_up_read;
static t_copy_from_user   kp_copy_from_user;

/* -----------------------------------------------------------------------
 * iovec for process_vm_rw
 * --------------------------------------------------------------------- */
struct kpm_iovec { void *iov_base; uint64_t iov_len; };

/* -----------------------------------------------------------------------
 * VMA walk offsets (arm64, common 4.x–6.x)
 * --------------------------------------------------------------------- */
#define MM_MMAP_OFFSET      0x40
#define MM_MMAP_LOCK_OFFSET 0x58
#define VMA_VM_NEXT         0x08
#define VMA_VM_FILE         0xd0

static inline struct vm_area_struct *mm_mmap(struct mm_struct *mm)
{
    return *(struct vm_area_struct **)((char *)mm + MM_MMAP_OFFSET);
}
static inline uint64_t vma_vm_start(struct vm_area_struct *v)
{
    return *(uint64_t *)v;
}
static inline struct vm_area_struct *vma_vm_next(struct vm_area_struct *v)
{
    return *(struct vm_area_struct **)((char *)v + VMA_VM_NEXT);
}
static inline void *vma_vm_file(struct vm_area_struct *v)
{
    return *(void **)((char *)v + VMA_VM_FILE);
}
/* file::f_path at offset 0x10 on arm64 */
static inline struct path *file_path(void *filp)
{
    return (struct path *)((char *)filp + 0x10);
}

/* Inline strstr (bare-metal gcc emits kf_strstr libcall otherwise) */
static const char *kpm_strstr(const char *h, const char *n)
{
    if (!*n) return h;
    for (; *h; h++) {
        const char *a = h, *b = n;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return h;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Cross-process memory helper
 * --------------------------------------------------------------------- */
static long xmem(int32_t pid, uint64_t addr, void *buf, uint64_t sz, int wr)
{
    struct pid *p = kp_find_get_pid(pid);
    if (!p) return -3;
    struct task_struct *t = kp_get_pid_task(p, PIDTYPE_PID);
    kp_put_pid(p);
    if (!t) return -3;
    struct kpm_iovec li = { buf,         sz };
    struct kpm_iovec ri = { (void *)addr, sz };
    ssize_t r = kp_process_vm_rw(t,
                (const struct iovec *)&li, 1,
                (const struct iovec *)&ri, 1,
                0, wr);
    kp_put_task_struct(t);
    return (r == (ssize_t)sz) ? 0 : -5;
}

/* -----------------------------------------------------------------------
 * Module base via VMA walk
 * --------------------------------------------------------------------- */
static uint64_t module_base(int32_t pid, const char *name)
{
    struct pid *p = kp_find_get_pid(pid);
    if (!p) return 0;
    struct task_struct *t = kp_get_pid_task(p, PIDTYPE_PID);
    kp_put_pid(p);
    if (!t) return 0;
    struct mm_struct *mm = kp_get_task_mm(t);
    kp_put_task_struct(t);
    if (!mm) return 0;

    char *pg = (char *)kp_get_zeroed_page(GFP_ATOMIC);
    if (!pg) { kp_mmput(mm); return 0; }

    kp_down_read((char *)mm + MM_MMAP_LOCK_OFFSET);

    uint64_t base = 0;
    for (struct vm_area_struct *v = mm_mmap(mm); v; v = vma_vm_next(v)) {
        void *f = vma_vm_file(v);
        if (!f) continue;
        char *path = kp_d_path(file_path(f), pg, PAGE_SIZE);
        if ((uint64_t)path > (uint64_t)-4096ULL) continue;
        const char *fname = path, *sl = 0;
        for (const char *c = path; *c; c++) if (*c == '/') sl = c;
        if (sl) fname = sl + 1;
        if (kpm_strstr(fname, name)) { base = vma_vm_start(v); break; }
    }

    kp_up_read((char *)mm + MM_MMAP_LOCK_OFFSET);
    kp_free_pages((uint64_t)pg, 0);
    kp_mmput(mm);
    return base;
}

/* -----------------------------------------------------------------------
 * ioctl handler
 * --------------------------------------------------------------------- */
static long wanbai_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case OP_INIT_KEY: {
        char key[0x100];
        return kp_copy_from_user(key, (void *)arg, sizeof(key)) ? -14 : 0;
    }
    case OP_READ_MEM: {
        COPY_MEMORY cm;
        if (kp_copy_from_user(&cm, (void *)arg, sizeof(cm))) return -14;
        if (!cm.size || cm.size > 0x1000000ULL) return -22;
        void *tmp = kp_kmalloc(cm.size, GFP_KERNEL);
        if (!tmp) return -12;
        long r = xmem(cm.pid, cm.addr, tmp, cm.size, 0);
        if (!r && compat_copy_to_user((void *)cm.buffer, tmp, cm.size)) r = -14;
        kp_kfree(tmp);
        return r;
    }
    case OP_WRITE_MEM: {
        COPY_MEMORY cm;
        if (kp_copy_from_user(&cm, (void *)arg, sizeof(cm))) return -14;
        if (!cm.size || cm.size > 0x1000000ULL) return -22;
        void *tmp = kp_kmalloc(cm.size, GFP_KERNEL);
        if (!tmp) return -12;
        long r = kp_copy_from_user(tmp, (void *)cm.buffer, cm.size)
                 ? -14 : xmem(cm.pid, cm.addr, tmp, cm.size, 1);
        kp_kfree(tmp);
        return r;
    }
    case OP_MODULE_BASE: {
        MODULE_BASE mb;
        if (kp_copy_from_user(&mb, (void *)arg, sizeof(mb))) return -14;
        char nb[256];
        if (compat_strncpy_from_user(nb, (char *)mb.name, sizeof(nb)) <= 0) return -14;
        nb[255] = '\0';
        mb.base = module_base(mb.pid, nb);
        return compat_copy_to_user((void *)arg, &mb, sizeof(mb)) ? -14 : 0;
    }
    default: return -25;
    }
}

/* -----------------------------------------------------------------------
 * Device node pointers (dynamically allocated to avoid ABI overflows
 * and Read-Only .data permission panics on some kernels)
 * --------------------------------------------------------------------- */
static struct kpm_file_operations *p_wanbai_fops;
static struct kpm_miscdevice      *p_wanbai_dev;

/* -----------------------------------------------------------------------
 * KPM lifecycle
 * --------------------------------------------------------------------- */
static long wanbai_init(const char *args, const char *event, void *__user rsv)
{
    if (!kallsyms_lookup_name) {
        printk(KERN_ERR "wanbai: kallsyms_lookup_name unavailable\n");
        return -2;
    }

    int missing = 0;

#define RESOLVE(var, sym) \
    var = (typeof(var))kallsyms_lookup_name(sym); \
    if (!var) { printk(KERN_ERR "wanbai: missing: " sym "\n"); missing++; }

    RESOLVE(kp_find_get_pid,    "find_get_pid");
    RESOLVE(kp_get_pid_task,    "get_pid_task");
    RESOLVE(kp_put_pid,         "put_pid");
    RESOLVE(kp_put_task_struct, "__put_task_struct");
    RESOLVE(kp_get_task_mm,     "get_task_mm");
    RESOLVE(kp_mmput,           "mmput");
    RESOLVE(kp_process_vm_rw,   "process_vm_rw");
    RESOLVE(kp_misc_register,   "misc_register");
    RESOLVE(kp_misc_deregister, "misc_deregister");
    RESOLVE(kp_kmalloc,         "__kmalloc");
    RESOLVE(kp_kfree,           "kfree");
    RESOLVE(kp_get_zeroed_page, "get_zeroed_page");
    RESOLVE(kp_free_pages,      "free_pages");
    RESOLVE(kp_d_path,          "d_path");
    RESOLVE(kp_down_read,       "down_read");
    RESOLVE(kp_up_read,         "up_read");

    /* copy_from_user depends on arm64 kernel version */
    kp_copy_from_user = (t_copy_from_user)kallsyms_lookup_name("_copy_from_user");
    if (!kp_copy_from_user) {
        kp_copy_from_user = (t_copy_from_user)kallsyms_lookup_name("__arch_copy_from_user");
    }
    if (!kp_copy_from_user) {
        printk(KERN_ERR "wanbai: missing: [__arch]_copy_from_user\n");
        missing++;
    }

    if (missing > 0) {
        printk(KERN_ERR "wanbai: %d symbols missing, aborting\n", missing);
        return -2;
    }

    printk(KERN_INFO "wanbai: symbols OK\n");

    /* Allocate 4096 bytes each to guarantee ABI overflow margin */
    p_wanbai_fops = kp_kmalloc(4096, GFP_KERNEL);
    p_wanbai_dev  = kp_kmalloc(4096, GFP_KERNEL);

    if (!p_wanbai_fops || !p_wanbai_dev) {
        printk(KERN_ERR "wanbai: kmalloc failed\n");
        if (p_wanbai_fops) kp_kfree(p_wanbai_fops);
        if (p_wanbai_dev)  kp_kfree(p_wanbai_dev);
        return -12; /* ENOMEM */
    }

    /* Zero out unconditionally (memset equivalent) */
    char *p1 = (char *)p_wanbai_fops;
    char *p2 = (char *)p_wanbai_dev;
    for (int i = 0; i < 4096; i++) { p1[i] = 0; p2[i] = 0; }

    /* Set up file_operations */
    p_wanbai_fops->unlocked_ioctl = wanbai_ioctl;
    p_wanbai_fops->compat_ioctl   = wanbai_ioctl;

    /* Set up miscdevice */
    p_wanbai_dev->minor = MISC_DYNAMIC_MINOR;
    p_wanbai_dev->name  = "wanbai";
    p_wanbai_dev->fops  = p_wanbai_fops;
    p_wanbai_dev->mode  = 0600;

    int ret = kp_misc_register(p_wanbai_dev);
    if (ret) {
        printk(KERN_ERR "wanbai: misc_register failed: %d\n", ret);
        kp_kfree(p_wanbai_fops);
        kp_kfree(p_wanbai_dev);
        p_wanbai_fops = 0;
        p_wanbai_dev = 0;
    } else {
        printk(KERN_INFO "wanbai: /dev/wanbai ready\n");
    }
    return ret;
}

static long wanbai_exit(void *__user rsv)
{
    if (kp_misc_deregister && p_wanbai_dev) {
        kp_misc_deregister(p_wanbai_dev);
    }
    if (p_wanbai_dev)  { kp_kfree(p_wanbai_dev);  p_wanbai_dev = 0; }
    if (p_wanbai_fops) { kp_kfree(p_wanbai_fops); p_wanbai_fops = 0; }

    printk(KERN_INFO "wanbai: unloaded\n");
    return 0;
}

static long wanbai_ctl0(const char *args, char *__user out, int outlen) { return 0; }
static long wanbai_ctl1(void *a1, void *a2, void *a3) { return 0; }

KPM_INIT(wanbai_init);
KPM_EXIT(wanbai_exit);
KPM_CTL0(wanbai_ctl0);
KPM_CTL1(wanbai_ctl1);
