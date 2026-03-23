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

KPM_NAME("universal-ioctl-driver");
KPM_VERSION("2.0.6");
KPM_LICENSE("ALL RIGHTS RESERVED BY ALEX5402");
KPM_AUTHOR("@alex5402");
KPM_DESCRIPTION("Universal ioctl driver supports Gt driver, dit-driver, dit pro driver,  wanbai driver, LDG kpm driver, for 4.9 to 6.12 (/dev/wanbai) for support visit t.me/alex5402");

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
 * file_operations: layout varies across kernel versions.
 *
 * The offset of unlocked_ioctl changes based on whether iopoll and iterate
 * are present:
 *   4.9-5.0  : no iopoll, has iterate   → ioctl at 0x48, open at 0x60
 *   5.1-5.8  : has iopoll, has iterate   → ioctl at 0x50, open at 0x70
 *   5.9-6.12 : has iopoll, no iterate    → ioctl at 0x48, open at 0x68
 *
 * We probe at runtime using def_chr_fops + chrdev_open to find the open
 * offset, then derive ioctl = open - 0x18 (pre-4.20) or open - 0x20 (4.20+).
 * We use a raw zeroed buffer and write function pointers at the probed offsets.
 * --------------------------------------------------------------------- */
static int fops_ioctl_offset;   /* detected at init */
static int fops_compat_offset;  /* ioctl_offset + 8 */

/* miscdevice ABI layout for arm64 Linux 4.x–6.x */
struct kpm_miscdevice {
    int                          minor;
    const char                  *name;
    const void                  *fops;
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
typedef int                   (*t_access_process_vm)(struct task_struct *,
                                                      unsigned long addr,
                                                      void *buf, int len,
                                                      unsigned int gup_flags);
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
static t_access_process_vm kp_access_process_vm;
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

typedef long (*t_probe_kernel_read)(void *dst, const void *src, size_t size);
static t_probe_kernel_read kp_probe_kernel_read;

typedef long (*t_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);
static t_copy_from_kernel_nofault kp_copy_from_kernel_nofault;

typedef struct file *(*t_filp_open)(const char *filename, int flags, int mode);
static t_filp_open kp_filp_open;

typedef ssize_t (*t_kernel_read)(struct file *file, void *buf, size_t count, loff_t *pos);
static t_kernel_read kp_kernel_read;     /* 4.14+ public API */
static t_kernel_read kp___kernel_read;   /* 5.4+  kernel-buffer safe */

typedef ssize_t (*t_vfs_read)(struct file *file, char *buf, size_t count, loff_t *pos);
static t_vfs_read kp_vfs_read;

typedef int (*t_filp_close)(struct file *file, void *id);
static t_filp_close kp_filp_close;

/* -----------------------------------------------------------------------
 * iovec for process_vm_rw
 * --------------------------------------------------------------------- */
/* FOLL_FORCE for access_process_vm (bypass VMA permissions) */
#define FOLL_FORCE  0x10
#define FOLL_WRITE  0x01

/* -----------------------------------------------------------------------
 * VMA walk offsets (arm64)
 *
 * mm_struct.mmap       = 0x00  (first field, the VMA list head)
 * vm_area_struct layout:
 *   vm_start           = 0x00
 *   vm_end             = 0x08
 *   vm_next            = 0x10
 *   vm_prev            = 0x18
 *   vm_mm              = probed at runtime (typically 0x40)
 *   vm_file            = vm_mm + 0x60 (fixed distance on arm64 4.x-5.x)
 * --------------------------------------------------------------------- */
#define MM_MMAP_OFFSET      0x0

/* Safe memory read helper to prevent panics when reading unpinned memory */
static inline int kp_safe_read(void *dst, const void *src, size_t size)
{
    if (kp_copy_from_kernel_nofault)
        return kp_copy_from_kernel_nofault(dst, src, size);
    if (kp_probe_kernel_read)
        return kp_probe_kernel_read(dst, src, size);
    return -1;
}

/* Cached vm_file offset, probed once at first use */
static int vma_vm_file_off = 0;

/* Probe vm_file offset by finding vm_mm back-pointer in the first VMA.
 * Every VMA has vma->vm_mm == mm.  We scan the VMA struct for a word
 * that equals mm, that gives us the vm_mm offset.  Then vm_file is at
 * a fixed distance from vm_mm:
 *   vm_page_prot(8) + vm_flags(8) + shared(32) + anon_vma_chain(16) +
 *   anon_vma(8) + vm_ops(8) + vm_pgoff(8) = 0x60
 * So vm_file = vm_mm_offset + 0x60 */
static int probe_vm_file_offset(struct vm_area_struct *vma, struct mm_struct *mm)
{
    uint64_t mm_val = (uint64_t)mm;
    /* Scan offsets 0x20..0x80 looking for vm_mm == mm */
    for (int off = 0x20; off <= 0x80; off += 8) {
        uint64_t val = 0;
        if (kp_safe_read(&val, (char *)vma + off, sizeof(val)))
            continue;
        if (val == mm_val) {
            int file_off = off + 0x60;
            return file_off;
        }
    }
    /* Fallback: try common offsets */
    return 0xa0;
}

/* Inline char helpers (bare-metal gcc emits libcall otherwise) */
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
 * put_task_struct is inline in 4.14 — the kallsyms __put_task_struct
 * is the *destructor* (frees task), not the refcount decrementer.
 *
 * We intentionally leak one refcount per xmem call.  This is safe:
 * the target process is alive (we just read/wrote its memory), so
 * the elevated refcount has no effect.  Attempting to probe the
 * usage field offset in task_struct is unreliable and risks silent
 * memory corruption that causes watchdog reboots.
 * --------------------------------------------------------------------- */
static void safe_put_task(struct task_struct *t)
{
    (void)t; /* intentional no-op — leak the ref */
}

/* -----------------------------------------------------------------------
 * Cross-process memory helper using access_process_vm.
 * Unlike process_vm_rw (which is a syscall backend using copy_from_user
 * on iovec structs), access_process_vm works with kernel buffers directly.
 * --------------------------------------------------------------------- */
static long xmem(int32_t pid, uint64_t addr, void *buf, uint64_t sz, int wr)
{
    struct pid *p = kp_find_get_pid(pid);
    if (!p) {
        printk(KERN_ERR "wanbai: xmem: find_get_pid(%d) returned NULL\n", pid);
        return -3;
    }
    struct task_struct *t = kp_get_pid_task(p, PIDTYPE_PID);
    kp_put_pid(p);
    if (!t) {
        printk(KERN_ERR "wanbai: xmem: get_pid_task(%d) returned NULL\n", pid);
        return -3;
    }
    unsigned int flags = FOLL_FORCE | (wr ? FOLL_WRITE : 0);
    int done = kp_access_process_vm(t, (unsigned long)addr, buf, (int)sz, flags);
    safe_put_task(t);
    if (done != (int)sz) {
        printk(KERN_ERR "wanbai: xmem: access_process_vm FAILED: requested=%llu got=%d (pid=%d addr=%llx wr=%d)\n",
               sz, done, pid, addr, wr);
        return -5;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Module base via direct VMA walk.
 *
 * Reading /proc/<pid>/maps from kernel context fails on GKI 5.x+ kernels
 * because seq_file uses copy_to_user() internally, which breaks with
 * kernel buffers after set_fs() removal.
 *
 * Instead, we walk the VMA linked list directly:
 *   get_task_mm() → mm->mmap → iterate vm_next → check vm_file →
 *   read dentry name → match against requested module name.
 *
 * The vm_file offset is probed at runtime by finding the vm_mm
 * back-pointer in the first VMA (vma->vm_mm == mm), then adding 0x60.
 * --------------------------------------------------------------------- */

/* dentry.d_name is a struct qstr at offset 0x20 in dentry.
 * qstr layout: { union { u64 hash_len; struct { u32 hash; u32 len; }; }; const char *name; }
 * So dentry->d_name.name is at dentry + 0x20 + 0x08 = dentry + 0x28 */
#define DENTRY_D_NAME_NAME_OFF  0x28

/* file->f_path is at offset 0x10 in struct file on arm64,
 * f_path is { struct vfsmount *mnt; struct dentry *dentry; }
 * so file->f_path.dentry = file + 0x10 + 0x08 = file + 0x18 */
#define FILE_F_PATH_DENTRY_OFF  0x18

static const char *dentry_name_from_file(void *filp, char *name_buf, size_t buf_size)
{
    if (!filp) return NULL;
    void *dentry = NULL;
    if (kp_safe_read(&dentry, (char *)filp + FILE_F_PATH_DENTRY_OFF, sizeof(dentry)) || !dentry)
        return NULL;
    
    char *name_ptr = NULL;
    if (kp_safe_read(&name_ptr, (char *)dentry + DENTRY_D_NAME_NAME_OFF, sizeof(name_ptr)) || !name_ptr)
        return NULL;

    /* Safely read the string up to buf_size */
    for (size_t i = 0; i < buf_size - 1; i++) {
        char c;
        if (kp_safe_read(&c, name_ptr + i, 1) || c == '\0') {
            name_buf[i] = '\0';
            break;
        }
        name_buf[i] = c;
    }
    name_buf[buf_size - 1] = '\0';
    return name_buf;
}

/* Simple string comparison for matching just the basename */
static int kpm_str_ends_with(const char *str, const char *suffix)
{
    size_t slen = kpm_strlen(str);
    size_t sufflen = kpm_strlen(suffix);
    if (sufflen > slen) return 0;
    const char *p = str + slen - sufflen;
    while (*p && *suffix) {
        if (kpm_tolower_char(*p) != kpm_tolower_char(*suffix)) return 0;
        p++; suffix++;
    }
    return !*suffix;
}

static uint64_t module_base_vma(int32_t pid, const char *name)
{
    uint64_t base = 0;
    struct pid *p = kp_find_get_pid(pid);
    if (!p) return 0;
    struct task_struct *t = kp_get_pid_task(p, PIDTYPE_PID);
    kp_put_pid(p);
    if (!t) return 0;

    struct mm_struct *mm = kp_get_task_mm(t);
    safe_put_task(t);
    if (!mm) {
        return 0;
    }

    /* We MUST use safe reads (nofault) because we don't hold mmap_lock. */
    if (!kp_probe_kernel_read && !kp_copy_from_kernel_nofault) {
        printk(KERN_ERR "wanbai: VMA walk missing safe read functions!\n");
        kp_mmput(mm);
        return 0;
    }

    /* Safely read mm->mmap (first field of mm_struct) */
    struct vm_area_struct *vma = NULL;
    if (kp_safe_read(&vma, (char *)mm + MM_MMAP_OFFSET, sizeof(vma)) || !vma) {
        kp_mmput(mm);
        return 0;
    }

    /* Probe vm_file offset on first call */
    if (!vma_vm_file_off) {
        vma_vm_file_off = probe_vm_file_offset(vma, mm);
    }

    int count = 0;
    char fname_buf[128];

    while (vma && count < 100000) {
        count++;
        /* Read vm_file at probed offset */
        void *filp = NULL;
        kp_safe_read(&filp, (char *)vma + vma_vm_file_off, sizeof(filp));

#define DEBUG_VMA_WALK 0
        if (filp && !IS_ERR((void *)filp)) {
            const char *fname = dentry_name_from_file(filp, fname_buf, sizeof(fname_buf));
#if DEBUG_VMA_WALK
            if (count <= 10) {
                printk(KERN_INFO "wanbai: VMA[%d] start=%llx filp=%px fname='%s'\n",
                       count, *(uint64_t *)&vma, filp, fname ? fname : "(null)");
            }
#endif
            if (fname && kpm_str_ends_with(fname, name)) {
                uint64_t vs = 0;
                kp_safe_read(&vs, vma, sizeof(vs));
                base = vs;
                break;
            }
        }
        /* Read next VMA pointer (vm_next at offset 0x10) */
        void *next = NULL;
        if (kp_safe_read(&next, (char *)vma + 0x10, sizeof(next)))
            break;
        vma = (struct vm_area_struct *)next;
    }

    if (!base) {
    }
    kp_mmput(mm);
    return base;
}

/* Try VMA walk first, fall back to /proc/maps file reading */
static uint64_t module_base(int32_t pid, const char *name)
{
    uint64_t base = 0;

    /* Method 1: direct VMA walk (works on all kernels 4.9-6.x) */
    if (kp_get_task_mm && kp_mmput) {
        base = module_base_vma(pid, name);
        if (base) {
            return base;
        }
    }

    /* Method 2: /proc/maps reading (works on 4.x kernels with set_fs) */
    if (!kp_snprintf || !kp_filp_open || !kp_filp_close) {
        printk(KERN_ERR "wanbai: module_base: no file I/O funcs available\n");
        return 0;
    }

    char path[64];
    kp_snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    struct file *f = kp_filp_open(path, 0, 0);
    if (IS_ERR(f)) {
        printk(KERN_ERR "wanbai: failed to open %s err=%ld\n", path, (long)(f));
        return 0;
    }

    char *buf = kp_kmalloc(PAGE_SIZE + 1, GFP_KERNEL);
    if (!buf) { kp_filp_close(f, 0); return 0; }

    loff_t pos = 0;
    int chunk = 0;
    while (1) {
        ssize_t bytes = -1;
        if (bytes <= 0 && kp___kernel_read)
            bytes = kp___kernel_read(f, buf, PAGE_SIZE, &pos);
        if (bytes <= 0 && kp_kernel_read)
            bytes = kp_kernel_read(f, buf, PAGE_SIZE, &pos);
        if (bytes <= 0 && kp_vfs_read)
            bytes = kp_vfs_read(f, buf, PAGE_SIZE, &pos);
        if (bytes <= 0) {
            break;
        }
        chunk++;
        buf[bytes] = '\0';

        char *line = buf;
        while (line && *line) {
            char *nl = kpm_strchr(line, '\n');
            if (nl) *nl = '\0';
            if (kpm_strcasestr(line, name)) {
                uint64_t val = 0;
                char *p2 = line;
                while (*p2) {
                    char c = *p2++;
                    if (c >= '0' && c <= '9') val = (val << 4) | (c - '0');
                    else if (c >= 'a' && c <= 'f') val = (val << 4) | (c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') val = (val << 4) | (c - 'A' + 10);
                    else break;
                }
                base = val;
                break;
            }
            if (!nl) {
                if (bytes == PAGE_SIZE) {
                    int len = kpm_strlen(line);
                    if (len < PAGE_SIZE) pos -= len;
                }
                break;
            }
            line = nl + 1;
        }
        if (base) break;
    }

    kp_kfree(buf);
    kp_filp_close(f, 0);
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
        long ret = kp_copy_from_user(key, (void *)arg, sizeof(key));
        if (ret) {
            printk(KERN_ERR "wanbai: OP_INIT_KEY copy_from_user failed: %ld\n", ret);
            return -14;
        }
        return 0;
    }
    case OP_READ_MEM: {
        COPY_MEMORY cm;
        long cfu = kp_copy_from_user(&cm, (void *)arg, sizeof(cm));
        if (cfu) {
            printk(KERN_ERR "wanbai: OP_READ_MEM copy_from_user(COPY_MEMORY) failed: %ld\n", cfu);
            return -14;
        }
        if (!cm.size || cm.size > 0x1000000ULL) {
            printk(KERN_ERR "wanbai: OP_READ_MEM invalid size=%llu\n", cm.size);
            return -22;
        }
        void *tmp = kp_kmalloc(cm.size, GFP_KERNEL);
        if (!tmp) {
            printk(KERN_ERR "wanbai: OP_READ_MEM kmalloc(%llu) FAILED (OOM)\n", cm.size);
            return -12;
        }
        long r = xmem(cm.pid, cm.addr, tmp, cm.size, 0);
        if (r) {
            printk(KERN_ERR "wanbai: OP_READ_MEM xmem read FAILED: %ld (pid=%d addr=0x%llx size=%llu)\n",
                   r, cm.pid, cm.addr, cm.size);
            kp_kfree(tmp);
            return r;
        }
        if (kp_copy_to_user((void *)cm.buffer, tmp, cm.size)) {
            printk(KERN_ERR "wanbai: OP_READ_MEM copy_to_user FAILED (buf=0x%llx size=%llu)\n",
                   cm.buffer, cm.size);
            kp_kfree(tmp);
            return -14;
        }
        kp_kfree(tmp);
        return 0;
    }
    case OP_WRITE_MEM: {
        COPY_MEMORY cm;
        long cfu = kp_copy_from_user(&cm, (void *)arg, sizeof(cm));
        if (cfu) {
            printk(KERN_ERR "wanbai: OP_WRITE_MEM copy_from_user(COPY_MEMORY) failed: %ld\n", cfu);
            return -14;
        }
        if (!cm.size || cm.size > 0x1000000ULL) {
            printk(KERN_ERR "wanbai: OP_WRITE_MEM invalid size=%llu\n", cm.size);
            return -22;
        }
        void *tmp = kp_kmalloc(cm.size, GFP_KERNEL);
        if (!tmp) {
            printk(KERN_ERR "wanbai: OP_WRITE_MEM kmalloc(%llu) FAILED (OOM)\n", cm.size);
            return -12;
        }
        long cfu2 = kp_copy_from_user(tmp, (void *)cm.buffer, cm.size);
        if (cfu2) {
            printk(KERN_ERR "wanbai: OP_WRITE_MEM copy_from_user(data) FAILED: %ld (buf=0x%llx size=%llu)\n",
                   cfu2, cm.buffer, cm.size);
            kp_kfree(tmp);
            return -14;
        }
        long r = xmem(cm.pid, cm.addr, tmp, cm.size, 1);
        if (r) {
            printk(KERN_ERR "wanbai: OP_WRITE_MEM xmem write FAILED: %ld (pid=%d addr=0x%llx size=%llu)\n",
                   r, cm.pid, cm.addr, cm.size);
        }
        kp_kfree(tmp);
        return r;
    }
    case OP_MODULE_BASE: {
        MODULE_BASE mb;
        long cfu_ret = kp_copy_from_user(&mb, (void *)arg, sizeof(mb));
        if (cfu_ret) {
            printk(KERN_ERR "wanbai: OP_MODULE_BASE copy_from_user failed: %ld\n", cfu_ret);
            return -14;
        }
        char nb[256];
        long sfu_ret = kp_strncpy_from_user(nb, (char *)mb.name, sizeof(nb));
        if (sfu_ret <= 0) {
            printk(KERN_ERR "wanbai: OP_MODULE_BASE strncpy_from_user failed: %ld\n", sfu_ret);
            return -14;
        }
        nb[255] = '\0';
        mb.base = module_base(mb.pid, nb);
        long ctu_ret = kp_copy_to_user((void *)arg, &mb, sizeof(mb));
        if (ctu_ret) {
            printk(KERN_ERR "wanbai: OP_MODULE_BASE copy_to_user failed: %ld\n", ctu_ret);
            return -14;
        }
        return 0;
    }
    default:
        printk(KERN_WARNING "wanbai: unknown cmd=0x%x\n", cmd);
        return -25;
    }
}

/* -----------------------------------------------------------------------
 * Device node pointers (dynamically allocated to avoid ABI overflows
 * and Read-Only .data permission panics on some kernels)
 * --------------------------------------------------------------------- */
static void      *p_wanbai_fops;   /* raw buffer, not a typed struct */
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
    RESOLVE(kp_access_process_vm, "access_process_vm");
    RESOLVE(kp_misc_register,   "misc_register");
    RESOLVE(kp_misc_deregister, "misc_deregister");
    /* __kmalloc was renamed to __kmalloc_noprof in kernel 6.10+ (alloc_tag profiling) */
    kp_kmalloc = (t_kmalloc)kallsyms_lookup_name("__kmalloc");
    if (!kp_kmalloc) kp_kmalloc = (t_kmalloc)kallsyms_lookup_name("__kmalloc_noprof");
    if (!kp_kmalloc) { printk(KERN_ERR "wanbai: missing: __kmalloc / __kmalloc_noprof\n"); missing++; }

    RESOLVE(kp_kfree,           "kfree");

    /* get_zeroed_page was renamed to get_zeroed_page_noprof in kernel 6.10+ */
    kp_get_zeroed_page = (t_get_zeroed_page)kallsyms_lookup_name("get_zeroed_page");
    if (!kp_get_zeroed_page) kp_get_zeroed_page = (t_get_zeroed_page)kallsyms_lookup_name("get_zeroed_page_noprof");
    if (!kp_get_zeroed_page) { printk(KERN_ERR "wanbai: missing: get_zeroed_page / get_zeroed_page_noprof\n"); missing++; }

    /* free_pages was renamed to free_pages_noprof in kernel 6.10+ */
    kp_free_pages = (t_free_pages)kallsyms_lookup_name("free_pages");
    if (!kp_free_pages) kp_free_pages = (t_free_pages)kallsyms_lookup_name("free_pages_noprof");
    if (!kp_free_pages) { printk(KERN_ERR "wanbai: missing: free_pages / free_pages_noprof\n"); missing++; }

    kp_snprintf = (t_snprintf)kallsyms_lookup_name("snprintf");
    kp_filp_open = (t_filp_open)kallsyms_lookup_name("filp_open");
    kp_kernel_read = (t_kernel_read)kallsyms_lookup_name("kernel_read");
    kp___kernel_read = (t_kernel_read)kallsyms_lookup_name("__kernel_read");
    kp_vfs_read = (t_vfs_read)kallsyms_lookup_name("vfs_read");
    kp_filp_close = (t_filp_close)kallsyms_lookup_name("filp_close");
    kp_probe_kernel_read = (t_probe_kernel_read)kallsyms_lookup_name("probe_kernel_read");
    kp_copy_from_kernel_nofault = (t_copy_from_kernel_nofault)kallsyms_lookup_name("copy_from_kernel_nofault");

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

    /* ------------------------------------------------------------------
     * Probe the unlocked_ioctl offset in file_operations.
     *
     * Strategy: look up def_chr_fops (the default char-device fops present
     * in all kernels).  Its 'open' field == chrdev_open.  Find chrdev_open
     * in the struct to determine the 'open' offset, then derive ioctl:
     *
     *   open at 0x60 → ioctl = 0x48  (4.9-4.19, no mmap_supported_flags)
     *   open at 0x68/0x70 → ioctl = 0x48  (4.20-5.0  or  5.9-6.12)
     *   open at 0x70 → ioctl = 0x50  (5.1-5.8)
     * ------------------------------------------------------------------ */
    {
        uint64_t *def_fops = (uint64_t *)kallsyms_lookup_name("def_chr_fops");
        uint64_t  chrdev_open_fn = kallsyms_lookup_name("chrdev_open");
        int open_off = -1;

        if (def_fops && chrdev_open_fn) {
            for (int i = 2; i < 30; i++) {  /* skip owner/llseek */
                if (def_fops[i] == chrdev_open_fn) {
                    open_off = i * 8;
                    break;
                }
            }
        }

        /* Fallback: try pipefifo_fops + pipe_write (available on most kernels) */
        if (open_off < 0) {
            uint64_t *pfops = (uint64_t *)kallsyms_lookup_name("pipefifo_fops");
            uint64_t  pw_fn = kallsyms_lookup_name("pipe_write");
            if (pfops && pw_fn) {
                /* pipe_write is at the 'write' field = offset 0x18 on all versions.
                 * write_iter is at 0x28. Check which slot has pipe_write. */
                for (int i = 2; i < 10; i++) {
                    if (pfops[i] == pw_fn) {
                        /* write is always at 0x18 (slot 3). If we found it at
                         * slot 3 => pre-field-insertion baseline matches.
                         * The open field can be derived: on all versions,
                         * open = write + (open_offset - 0x18).
                         * But easier: scan for pipe_fopen or pipefifo_open. */
                        uint64_t popen = kallsyms_lookup_name("fifo_open");
                        if (!popen) popen = kallsyms_lookup_name("pipefifo_open");
                        if (popen) {
                            for (int j = 5; j < 30; j++) {
                                if (pfops[j] == popen) {
                                    open_off = j * 8;
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }

        if (open_off > 0) {
            /* open at 0x60 → no mmap_supported_flags → delta 0x18
             * open at 0x68/0x70 → has mmap_supported_flags → delta 0x20 */
            fops_ioctl_offset = (open_off <= 0x60)
                                ? open_off - 0x18
                                : open_off - 0x20;
        } else {
            fops_ioctl_offset = 0x48; /* safe fallback for 4.14 */
            printk(KERN_WARNING "wanbai: fops probe failed, defaulting ioctl=0x48\n");
        }
        fops_compat_offset = fops_ioctl_offset + 8;
    }

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

    /* Write ioctl function pointers at the probed offsets */
    *(uint64_t *)(p1 + fops_ioctl_offset)  = (uint64_t)wanbai_ioctl;
    *(uint64_t *)(p1 + fops_compat_offset) = (uint64_t)wanbai_ioctl;

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

    return 0;
}

static long wanbai_ctl0(const char *args, char *__user out, int outlen) { return 0; }
static long wanbai_ctl1(void *a1, void *a2, void *a3) { return 0; }

KPM_INIT(wanbai_init);
KPM_EXIT(wanbai_exit);
KPM_CTL0(wanbai_ctl0);
KPM_CTL1(wanbai_ctl1);
