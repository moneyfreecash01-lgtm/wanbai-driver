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

/* Matches userspace COPY_MEMORY: pid_t(4) + pad(4) + uintptr_t(8) + void*(8) + size_t(8) */
typedef struct {
    int32_t   pid;
    uint32_t  _pad;
    uint64_t  addr;
    uint64_t  buffer;
    uint64_t  size;
} COPY_MEMORY;

/* Matches userspace MODULE_BASE: pid_t(4) + pad(4) + char*(8) + uintptr_t(8) */
typedef struct {
    int32_t   pid;
    uint32_t  _pad;
    uint64_t  name;   /* userspace char* pointer */
    uint64_t  base;
} MODULE_BASE;


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
static t_copy_from_user   kp_copy_from_user;
static t_copy_from_user   kp_copy_to_user; /* Signature is identical */
typedef long (*t_strncpy_from_user)(char *, const char *, long);
static t_strncpy_from_user kp_strncpy_from_user;

typedef int (*t_snprintf)(char *buf, size_t size, const char *fmt, ...);
static t_snprintf kp_snprintf;

typedef struct file *(*t_filp_open)(const char *filename, int flags, int mode);
static t_filp_open kp_filp_open;

typedef ssize_t (*t_kernel_read)(struct file *file, void *buf, size_t count, loff_t *pos);
static t_kernel_read kp_kernel_read;

typedef int (*t_filp_close)(struct file *file, void *id);
static t_filp_close kp_filp_close;

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
static void kpm_tolower(char *str) {
    while (*str) {
        if (*str >= 'A' && *str <= 'Z')
            *str = *str + ('a' - 'A');
        str++;
    }
}
static char kpm_tolower_char(char c) {
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}
static char *kpm_strcasestr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    for (; *haystack; haystack++) {
        if (kpm_tolower_char(*haystack) == kpm_tolower_char(*needle)) {
            const char *h, *n;
            for (h = haystack, n = needle; *h && *n; h++, n++) {
                if (kpm_tolower_char(*h) != kpm_tolower_char(*n)) break;
            }
            if (!*n) return (char *)haystack;
        }
    }
    return NULL;
}
static char *kpm_strchr(const char *s, int c) {
    while (*s != (char)c) {
        if (!*s++) return NULL;
    }
    return (char *)s;
}
static size_t kpm_strlen(const char *s) {
    const char *sc = s;
    for (; *sc != '\0'; ++sc) /* nothing */;
    return sc - s;
}

/* Helper to check for error pointers */
#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
static inline long IS_ERR(const void *ptr) {
    return IS_ERR_VALUE((unsigned long)ptr);
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
    char path[64];
    struct file *f;
    char *buf;
    loff_t pos = 0;
    uint64_t base = 0;

    printk(KERN_INFO "wanbai: module_base called pid=%d name=%s\n", pid, name);

    if (!kp_snprintf || !kp_filp_open || !kp_kernel_read || !kp_filp_close) {
        printk(KERN_INFO "wanbai: module_base missing kfuncs: snprintf=%p filp_open=%p kernel_read=%p filp_close=%p\n",
               kp_snprintf, kp_filp_open, kp_kernel_read, kp_filp_close);
        return 0;
    }

    kp_snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    printk(KERN_INFO "wanbai: opening %s\n", path);

    f = kp_filp_open(path, 0, 0); /* O_RDONLY = 0 */
    if (IS_ERR(f)) {
        printk(KERN_INFO "wanbai: failed to open %s err=%ld\n", path, (long)(f));
        return 0;
    }
    printk(KERN_INFO "wanbai: %s opened OK\n", path);

    buf = kp_kmalloc(PAGE_SIZE + 1, GFP_KERNEL);
    if (!buf) {
        kp_filp_close(f, 0);
        return 0;
    }

    int chunk = 0;
    while (1) {
        ssize_t bytes = kp_kernel_read(f, buf, PAGE_SIZE, &pos);
        if (bytes <= 0) {
            printk(KERN_INFO "wanbai: kernel_read chunk=%d bytes=%ld (done or error)\n", chunk, (long)bytes);
            break;
        }
        if (chunk == 0)
            printk(KERN_INFO "wanbai: first 64 bytes: %.64s\n", buf);
        chunk++;
        buf[bytes] = '\0';

        char *line = buf;
        while (line && *line) {
            char *nl = kpm_strchr(line, '\n');
            if (nl) *nl = '\0';

            if (kpm_strcasestr(line, name)) {
                uint64_t val = 0;
                char *p = line;
                while (*p) {
                    char c = *p++;
                    if (c >= '0' && c <= '9') val = (val << 4) | (c - '0');
                    else if (c >= 'a' && c <= 'f') val = (val << 4) | (c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') val = (val << 4) | (c - 'A' + 10);
                    else break;
                }
                base = val;
                printk(KERN_INFO "wanbai: found '%s' in line => base=%llx\n", name, base);
                break;
            }

            if (!nl) {
                if (bytes == PAGE_SIZE) {
                    int len = kpm_strlen(line);
                    if (len < PAGE_SIZE) {
                        pos -= len;
                    }
                }
                break;
            }
            line = nl + 1;
        }
        if (base) break;
    }

    kp_kfree(buf);
    kp_filp_close(f, 0);
    printk(KERN_INFO "wanbai: module_base result for %s = %llx\n", name, base);
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
        if (kp_strncpy_from_user(nb, (char *)mb.name, sizeof(nb)) <= 0) return -14;
        nb[255] = '\0';
        mb.base = module_base(mb.pid, nb);
        return kp_copy_to_user((void *)arg, &mb, sizeof(mb)) ? -14 : 0;
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

    kp_snprintf = (t_snprintf)kallsyms_lookup_name("snprintf");
    kp_filp_open = (t_filp_open)kallsyms_lookup_name("filp_open");
    kp_kernel_read = (t_kernel_read)kallsyms_lookup_name("kernel_read");
    kp_filp_close = (t_filp_close)kallsyms_lookup_name("filp_close");

    /* copy_from_user depends on arm64 kernel version */
    kp_copy_from_user = (t_copy_from_user)kallsyms_lookup_name("_copy_from_user");
    if (!kp_copy_from_user) kp_copy_from_user = (t_copy_from_user)kallsyms_lookup_name("__arch_copy_from_user");

    kp_copy_to_user = (t_copy_from_user)kallsyms_lookup_name("_copy_to_user");
    if (!kp_copy_to_user) kp_copy_to_user = (t_copy_from_user)kallsyms_lookup_name("__arch_copy_to_user");

    kp_strncpy_from_user = (t_strncpy_from_user)kallsyms_lookup_name("strncpy_from_user");

    if (!kp_copy_from_user || !kp_copy_to_user) {
        printk(KERN_ERR "wanbai: missing: [__arch]_copy_from_user\n");
        missing++;
    }

    if (!kp_strncpy_from_user) {
        printk(KERN_ERR "wanbai: missing: strncpy_from_user\n");
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
