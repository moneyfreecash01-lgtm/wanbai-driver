/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * gyro-driver – KPatch-Next KPM for gyroscope sensor spoofing
 *
 * Exposes /dev/alex_gyro for userspace control.
 * Hooks MTK's gyro_data_report() function to intercept and modify
 * gyroscope sensor data before it reaches Android SensorService / HAL.
 *
 * ioctl interface:
 *   GYRO_OP_SET_ACTIVE  (0x900) – enable/disable spoofing
 *   GYRO_OP_SET_ANGLES  (0x901) – set target pitch/yaw rad/s values
 *   GYRO_OP_GET_STATUS  (0x902) – read current hook/spoof state
 */

#include <compiler.h>
#include <kpmodule.h>
#include <ktypes.h>
#include <linux/printk.h>
#include <hook.h>

KPM_NAME("zerolag-gyro-driver");
KPM_VERSION("1.0.0");
KPM_LICENSE("ALL RIGHTS RESERVED BY ALEX5402");
KPM_AUTHOR("@alex5402");
KPM_DESCRIPTION("Kernel-level gyroscope spoofing via gyro_data_report hook by zerolag cheats (/dev/alex_gyro) ");

/* -----------------------------------------------------------------------
 * ioctl opcodes (must match userspace header)
 * --------------------------------------------------------------------- */
#define GYRO_OP_SET_ACTIVE  0x900
#define GYRO_OP_SET_ANGLES  0x901
#define GYRO_OP_GET_STATUS  0x902

/* Userspace structs — ALL integer, no FPU in kernel */
typedef struct {
    int32_t  active;   /* 1 = spoofing on, 0 = off */
} GYRO_ACTIVE;

typedef struct {
    int32_t  pitch;    /* pre-scaled offset to add to real sensor value */
    int32_t  yaw;      /* pre-scaled offset to add to real sensor value */
} GYRO_ANGLES;

typedef struct {
    int32_t  active;
    int32_t  hook_installed;
    int32_t  events_intercepted; /* rolling counter */
} GYRO_STATUS;

/* -----------------------------------------------------------------------
 * Global spoofing state (written by ioctl, read by hook)
 * --------------------------------------------------------------------- */
static volatile int32_t  g_spoof_active = 0;
static volatile int32_t  g_target_pitch = 0;  /* pre-scaled from userspace */
static volatile int32_t  g_target_yaw   = 0;  /* pre-scaled from userspace */
static volatile int32_t  g_events_intercepted = 0;
static volatile int32_t  g_hook_installed = 0;
static volatile int32_t  g_probe_done = 0;  /* 1 = struct layout probed */
static volatile int32_t  g_data_offset = -1; /* offset of x/y/z int32 values in sensor_event */

/* -----------------------------------------------------------------------
 * Opaque kernel types
 * --------------------------------------------------------------------- */
struct task_struct;
struct pid;
struct mm_struct;
struct file;
struct device;
struct input_dev;

#define GFP_KERNEL  0xcc0u
#define MISC_DYNAMIC_MINOR 255

/* input event types/codes from <linux/input-event-codes.h> */
#define EV_SYN  0x00
#define EV_ABS  0x03
#define EV_MSC  0x04
/* ABS codes for gyroscope axes */
#define ABS_RX  0x03
#define ABS_RY  0x04
#define ABS_RZ  0x05
/* Some devices use ABS_X/Y/Z for gyro */
#define ABS_X   0x00
#define ABS_Y   0x01
#define ABS_Z   0x02

/* -----------------------------------------------------------------------
 * file_operations offset (probed at runtime, same as wanbai)
 * --------------------------------------------------------------------- */
static int fops_ioctl_offset;
static int fops_compat_offset;

/* miscdevice ABI layout */
struct kpm_miscdevice {
    int                          minor;
    const char                  *name;
    const void                  *fops;
    struct { void *next; void *prev; } list;
    struct device               *parent;
    struct device               *this_device;
    const void                  *groups;
    const char                  *nodename;
    unsigned int                 mode;
};

/* -----------------------------------------------------------------------
 * Kernel function typedefs (resolved via kallsyms)
 * --------------------------------------------------------------------- */
typedef int   (*t_misc_register)(struct kpm_miscdevice *);
typedef void  (*t_misc_deregister)(struct kpm_miscdevice *);
typedef void *(*t_kmalloc)(uint64_t, uint32_t);
typedef void  (*t_kfree)(const void *);
typedef long  (*t_copy_from_user)(void *, const void *, uint64_t);
typedef long  (*t_copy_to_user)(void *, const void *, uint64_t);

static t_misc_register    kp_misc_register;
static t_misc_deregister  kp_misc_deregister;
static t_kmalloc          kp_kmalloc;
static t_kfree            kp_kfree;
static t_copy_from_user   kp_copy_from_user;
static t_copy_to_user     kp_copy_to_user;

/* -----------------------------------------------------------------------
 * input_event hooking via KPatch-Next hook_wrap4
 * --------------------------------------------------------------------- */
static uint64_t input_event_addr = 0;

/* -----------------------------------------------------------------------
 * input_dev name reading helper
 *
 * We need to identify if an input_dev is a gyroscope device.
 * struct input_dev has a 'name' field. On arm64 Linux 4.x-6.x:
 *   dev->name is typically at offset 0x08 or 0x10 (after dev->ev_type)
 *
 * We use a safe read approach and scan for known gyroscope device names.
 * --------------------------------------------------------------------- */
typedef long (*t_probe_kernel_read)(void *dst, const void *src, size_t size);
static t_probe_kernel_read kp_probe_kernel_read;

typedef long (*t_copy_from_kernel_nofault)(void *dst, const void *src, size_t size);
static t_copy_from_kernel_nofault kp_copy_from_kernel_nofault;

static inline int kp_safe_read(void *dst, const void *src, size_t size)
{
    if (kp_copy_from_kernel_nofault)
        return kp_copy_from_kernel_nofault(dst, src, size);
    if (kp_probe_kernel_read)
        return kp_probe_kernel_read(dst, src, size);
    return -1;
}

/* Inline string helpers (no libc in bare-metal KPM) */
static size_t kpm_strlen(const char *s) {
    const char *sc = s;
    for (; *sc != '\0'; ++sc);
    return sc - s;
}

static char kpm_tolower(char c) {
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

static char *kpm_strcasestr(const char *hay, const char *needle) {
    if (!*needle) return (char *)hay;
    for (; *hay; hay++) {
        if (kpm_tolower(*hay) == kpm_tolower(*needle)) {
            const char *h, *n;
            for (h = hay, n = needle; *h && *n; h++, n++) {
                if (kpm_tolower(*h) != kpm_tolower(*n)) break;
            }
            if (!*n) return (char *)hay;
        }
    }
    return NULL;
}

/* Before-handler for hook_wrap4 on gyro_data_report.
 *
 * MTK's gyro_data_report signature (from kernel source):
 *   int gyro_data_report(struct data_unit_t *data)
 *
 * data_unit_t is something like:
 *   struct data_unit_t {
 *       uint8_t  sensor_type;    // offset 0
 *       uint8_t  padding[3];
 *       uint32_t something;
 *       int64_t  timestamp;      // offset 8
 *       union {
 *           struct {
 *               int32_t x, y, z; // gyro values
 *           } gyro;
 *       };
 *   };
 *
 * The exact layout varies per kernel version, so we probe it.
 * hook_wrap4 gives us: arg0 = first function argument = data pointer
 */

static void gyro_before_handler(hook_fargs4_t *args, void *udata)
{
    (void)udata;

    char *data = (char *)args->arg0;
    if (!data) return;

    /* Validate pointer is in kernel space */
    if ((uint64_t)data < 0xffff000000000000ULL) return;

    /* Probe phase: dump the first 128 bytes to find x/y/z layout */
    if (!g_probe_done) {
        g_probe_done = 1;
        printk(KERN_INFO "alex_gyro: === PROBING gyro_data_report struct ===");
        printk(KERN_INFO "alex_gyro: data ptr = %px", data);

        /* Dump 128 bytes as uint32 words */
        for (int i = 0; i < 128; i += 4) {
            uint32_t w = 0;
            if (kp_safe_read(&w, data + i, 4)) break;
            int32_t sw = (int32_t)w;
            printk(KERN_INFO "alex_gyro: [%02d] 0x%08x (%d)", i, w, sw);
        }
        printk(KERN_INFO "alex_gyro: === END PROBE ===");
    }

    /* If spoofing is not active, just count */
    g_events_intercepted++;

    if (!g_spoof_active) return;
    if (g_target_pitch == 0 && g_target_yaw == 0) return;

    /* 
     * Apply offsets to the gyro x/y/z values.
     * Common MTK layouts for data_unit_t gyro data offset:
     *   - Newer kernels (5.x): offset 16 (x), 20 (y), 24 (z)
     *   - Older kernels (4.x): offset 8 (x), 12 (y), 16 (z)
     * We try to auto-detect by looking for non-zero int32 triplets.
     * Once we find it, we cache g_data_offset.
     */
    if (g_data_offset < 0) {
        /* Auto-detect: scan for first non-zero int32 triplet */
        static const int try_offsets[] = { 16, 8, 12, 20, 24, 28, 32 };
        for (int i = 0; i < 7; i++) {
            int32_t x = 0, y = 0, z = 0;
            int off = try_offsets[i];
            if (kp_safe_read(&x, data + off, 4)) continue;
            if (kp_safe_read(&y, data + off + 4, 4)) continue;
            if (kp_safe_read(&z, data + off + 8, 4)) continue;
            /* Gyro values are typically non-zero and in a reasonable range */
            if (x != 0 || y != 0 || z != 0) {
                if (x > -100000 && x < 100000 && y > -100000 && y < 100000) {
                    g_data_offset = off;
                    printk(KERN_INFO "alex_gyro: auto-detected data offset = %d (x=%d y=%d z=%d)",
                           off, x, y, z);
                    break;
                }
            }
        }
        if (g_data_offset < 0) return; /* Still unknown, skip */
    }

    /* Read current values */
    int32_t x = 0, y = 0;
    if (kp_safe_read(&x, data + g_data_offset, 4)) return;
    if (kp_safe_read(&y, data + g_data_offset + 4, 4)) return;

    /* Apply offsets from userspace */
    x += g_target_pitch;
    y += g_target_yaw;

    /* Write modified values back */
    *(int32_t *)(data + g_data_offset) = x;
    *(int32_t *)(data + g_data_offset + 4) = y;
}

/* -----------------------------------------------------------------------
 * ioctl handler
 * --------------------------------------------------------------------- */
static long gyro_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case GYRO_OP_SET_ACTIVE: {
        GYRO_ACTIVE ga;
        if (kp_copy_from_user(&ga, (void *)arg, sizeof(ga))) return -14;
        g_spoof_active = ga.active;
        printk(KERN_INFO "alex_gyro: spoofing %s\n",
               g_spoof_active ? "ENABLED" : "DISABLED");
        return 0;
    }
    case GYRO_OP_SET_ANGLES: {
        GYRO_ANGLES ga;
        if (kp_copy_from_user(&ga, (void *)arg, sizeof(ga))) return -14;
        g_target_pitch = ga.pitch;
        g_target_yaw   = ga.yaw;
        return 0;
    }
    case GYRO_OP_GET_STATUS: {
        GYRO_STATUS gs;
        gs.active = g_spoof_active;
        gs.hook_installed = g_hook_installed;
        gs.events_intercepted = g_events_intercepted;
        if (kp_copy_to_user((void *)arg, &gs, sizeof(gs))) return -14;
        return 0;
    }
    default:
        printk(KERN_INFO "alex_gyro: unknown cmd=0x%x\n", cmd);
        return -25;
    }
}

/* -----------------------------------------------------------------------
 * Device node pointers
 * --------------------------------------------------------------------- */
static void                  *p_gyro_fops;
static struct kpm_miscdevice *p_gyro_dev;

/* -----------------------------------------------------------------------
 * KPM lifecycle
 * --------------------------------------------------------------------- */
static long gyro_init(const char *args, const char *event, void *__user rsv)
{
    if (!kallsyms_lookup_name) {
        printk(KERN_ERR "alex_gyro: kallsyms_lookup_name unavailable\n");
        return -2;
    }

    int missing = 0;

#define RESOLVE(var, sym) \
    var = (typeof(var))kallsyms_lookup_name(sym); \
    if (!var) { printk(KERN_ERR "alex_gyro: missing: " sym "\n"); missing++; }

    RESOLVE(kp_misc_register,   "misc_register");
    RESOLVE(kp_misc_deregister, "misc_deregister");
    RESOLVE(kp_kmalloc,         "__kmalloc");
    RESOLVE(kp_kfree,           "kfree");

    /* copy_from_user variants */
    kp_copy_from_user = (t_copy_from_user)kallsyms_lookup_name("_copy_from_user");
    if (!kp_copy_from_user)
        kp_copy_from_user = (t_copy_from_user)kallsyms_lookup_name("__arch_copy_from_user");

    kp_copy_to_user = (t_copy_to_user)kallsyms_lookup_name("_copy_to_user");
    if (!kp_copy_to_user)
        kp_copy_to_user = (t_copy_to_user)kallsyms_lookup_name("__arch_copy_to_user");

    if (!kp_copy_from_user || !kp_copy_to_user) {
        printk(KERN_ERR "alex_gyro: missing copy_from/to_user\n");
        missing++;
    }

    /* Safe read functions for device name probing */
    kp_probe_kernel_read = (t_probe_kernel_read)kallsyms_lookup_name("probe_kernel_read");
    kp_copy_from_kernel_nofault = (t_copy_from_kernel_nofault)kallsyms_lookup_name("copy_from_kernel_nofault");

    if (!kp_probe_kernel_read && !kp_copy_from_kernel_nofault) {
        printk(KERN_WARNING "alex_gyro: no safe read functions — device detection limited\n");
    }

    if (missing > 0) {
        printk(KERN_ERR "alex_gyro: %d critical symbols missing, aborting\n", missing);
        return -2;
    }

    /* ------------------------------------------------------------------
     * Probe fops ioctl offset (same logic as wanbai)
     * ------------------------------------------------------------------ */
    {
        uint64_t *def_fops = (uint64_t *)kallsyms_lookup_name("def_chr_fops");
        uint64_t  chrdev_open_fn = kallsyms_lookup_name("chrdev_open");
        int open_off = -1;

        if (def_fops && chrdev_open_fn) {
            for (int i = 2; i < 30; i++) {
                if (def_fops[i] == chrdev_open_fn) {
                    open_off = i * 8;
                    break;
                }
            }
        }

        if (open_off < 0) {
            uint64_t *pfops = (uint64_t *)kallsyms_lookup_name("pipefifo_fops");
            uint64_t  pw_fn = kallsyms_lookup_name("pipe_write");
            if (pfops && pw_fn) {
                for (int i = 2; i < 10; i++) {
                    if (pfops[i] == pw_fn) {
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
            fops_ioctl_offset = (open_off <= 0x60)
                                ? open_off - 0x18
                                : open_off - 0x20;
            printk(KERN_INFO "alex_gyro: probed open=0x%x -> ioctl=0x%x\n",
                   open_off, fops_ioctl_offset);
        } else {
            fops_ioctl_offset = 0x48;
            printk(KERN_WARNING "alex_gyro: fops probe failed, defaulting ioctl=0x48\n");
        }
        fops_compat_offset = fops_ioctl_offset + 8;
    }

    /* ------------------------------------------------------------------
     * Allocate and register misc device
     * ------------------------------------------------------------------ */
    p_gyro_fops = kp_kmalloc(4096, GFP_KERNEL);
    p_gyro_dev  = kp_kmalloc(4096, GFP_KERNEL);

    if (!p_gyro_fops || !p_gyro_dev) {
        printk(KERN_ERR "alex_gyro: kmalloc failed\n");
        if (p_gyro_fops) kp_kfree(p_gyro_fops);
        if (p_gyro_dev)  kp_kfree(p_gyro_dev);
        return -12;
    }

    /* Zero out */
    char *p1 = (char *)p_gyro_fops;
    char *p2 = (char *)p_gyro_dev;
    for (int i = 0; i < 4096; i++) { p1[i] = 0; p2[i] = 0; }

    /* Write ioctl pointers */
    *(uint64_t *)(p1 + fops_ioctl_offset)  = (uint64_t)gyro_ioctl;
    *(uint64_t *)(p1 + fops_compat_offset) = (uint64_t)gyro_ioctl;

    p_gyro_dev->minor = MISC_DYNAMIC_MINOR;
    p_gyro_dev->name  = "alex_gyro";
    p_gyro_dev->fops  = p_gyro_fops;
    p_gyro_dev->mode  = 0666; /* world-readable for cheat process */

    int ret = kp_misc_register(p_gyro_dev);
    if (ret) {
        printk(KERN_ERR "alex_gyro: misc_register failed: %d\n", ret);
        kp_kfree(p_gyro_fops);
        kp_kfree(p_gyro_dev);
        p_gyro_fops = 0;
        p_gyro_dev = 0;
        return ret;
    }
    printk(KERN_INFO "alex_gyro: /dev/alex_gyro ready\n");

    /* ------------------------------------------------------------------
     * Install gyro_data_report hook (MTK sensor framework)
     * ------------------------------------------------------------------ */
    input_event_addr = kallsyms_lookup_name("gyro_data_report");
    if (!input_event_addr) {
        printk(KERN_WARNING "alex_gyro: gyro_data_report not found in kallsyms\n");
        printk(KERN_WARNING "alex_gyro: /dev/alex_gyro is UP but hook is NOT installed\n");
        printk(KERN_WARNING "alex_gyro: sensor spoofing will NOT work until hook is installed\n");
        return 0; /* Device node works, hook just isn't installed */
    }

    printk(KERN_INFO "alex_gyro: gyro_data_report at %llx\n", (uint64_t)input_event_addr);

    long hret = hook_wrap4((void *)input_event_addr,
                           (hook_chain4_callback)gyro_before_handler,
                           NULL, /* no after-handler */
                           NULL  /* no userdata */);
    if (hret == HOOK_NO_ERR) {
        g_hook_installed = 1;
        printk(KERN_INFO "alex_gyro: hook_wrap4 on gyro_data_report SUCCESS\n");
    } else {
        printk(KERN_ERR "alex_gyro: hook_wrap4 failed: %ld\n", hret);
        printk(KERN_WARNING "alex_gyro: device UP but hook NOT installed\n");
    }

    return 0;
}

static long gyro_exit(void *__user rsv)
{
    /* Unhook gyro_data_report */
    if (g_hook_installed && input_event_addr) {
        hook_unwrap((void *)input_event_addr, (void *)gyro_before_handler, NULL);
        g_hook_installed = 0;
        printk(KERN_INFO "alex_gyro: gyro_data_report hook removed\n");
    }

    /* Deregister device */
    if (kp_misc_deregister && p_gyro_dev) {
        kp_misc_deregister(p_gyro_dev);
    }
    if (p_gyro_dev)  { kp_kfree(p_gyro_dev);  p_gyro_dev = 0; }
    if (p_gyro_fops) { kp_kfree(p_gyro_fops); p_gyro_fops = 0; }

    g_spoof_active = 0;
    printk(KERN_INFO "alex_gyro: unloaded\n");
    return 0;
}

static long gyro_ctl0(const char *args, char *__user out, int outlen) { return 0; }
static long gyro_ctl1(void *a1, void *a2, void *a3) { return 0; }

KPM_INIT(gyro_init);
KPM_EXIT(gyro_exit);
KPM_CTL0(gyro_ctl0);
KPM_CTL1(gyro_ctl1);
