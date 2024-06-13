#include "qemu/osdep.h"

#include "cpu.h"
#include "sysemu/mshv_int.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include <sys/utsname.h>
#include "hw/i386/e820_memory_layout.h"
#include "hw/i386/x86.h"
#include "sysemu/sysemu.h"

static Notifier smram_machine_done;
static MshvMemoryListener smram_listener;
static AddressSpace smram_address_space;
static MemoryRegion smram_as_root;
static MemoryRegion smram_as_mem;

extern MshvState *mshv_state;

static uint64_t *test(void) {
    return g_malloc0(4);
}

static void register_smram_listener(Notifier *n, void *unused)
{
    uint64_t *x;
    mshv_debug();
    MemoryRegion *smram =
        (MemoryRegion *)object_resolve_path("/machine/smram", NULL);
    x = test();
    /* Outer container... */
    memory_region_init(&smram_as_root, OBJECT(mshv_state),
                       "mem-container-smram", ~0ull);
    memory_region_set_enabled(&smram_as_root, true);
    if (x) {x=test();}
    /* ... with two regions inside: normal system memory with low
     * priority, and...
     */
    memory_region_init_alias(&smram_as_mem, OBJECT(mshv_state), "mem-smram",
                             get_system_memory(), 0, ~0ull);
    memory_region_add_subregion_overlap(&smram_as_root, 0, &smram_as_mem, 0);
    memory_region_set_enabled(&smram_as_mem, true);
    if (x) {x=test();}
    if (smram) {
        /* ... SMRAM with higher priority */
        memory_region_add_subregion_overlap(&smram_as_root, 0, smram, 10);
        memory_region_set_enabled(smram, true);
    }
    if (x) {x=test();}
    address_space_init(&smram_address_space, &smram_as_root, "KVM-SMRAM");
    if (x) {x=test();}
    mshv_memory_listener_register(mshv_state, &smram_listener,
                                  &smram_address_space, 1, "kvm-smram");
    mshv_debug();
}

static RateLimit bus_lock_ratelimit_ctrl;
#define BUS_LOCK_SLICE_TIME 1000000000ULL /* ns */

bool mshv_arch_init(MachineState *ms, MshvState *s)
{
    uint64_t identity_base = 0xfffbc000;
    int ret;
    bool ok;
    struct utsname utsname;

    /*
     * Initialize SEV context, if required
    if (ms->cgs) {
        ret = confidential_guest_kvm_init(ms->cgs, &local_err);
        if (ret < 0) {
            error_report_err(local_err);
            return ret;
        }
    }
    */

    uname(&utsname);

    /*
     * On older Intel CPUs, KVM uses vm86 mode to emulate 16-bit code directly.
     * In order to use vm86 mode, an EPT identity map and a TSS  are needed.
     * Since these must be part of guest physical memory, we need to allocate
     * them, both by setting their start addresses in the kernel and by
     * creating a corresponding e820 entry. We need 4 pages before the BIOS,
     * so this value allows up to 16M BIOSes.
     */
    identity_base = 0xfeffc000;
    ok = mshv_set_identity_map_address(s->vm, identity_base);
    if (!ok) {
        mshv_log("Failed mshv_set_identity_map_address\n");
        ret = -1;
        return ret;
    }

    /* Set TSS base one page after EPT identity map. */
    ok = mshv_set_tss_address(s->vm, identity_base + 0x1000);
    if (!ok) {
        ret = -1;
        mshv_log("Failed mshv_set_tss_address\n");
        return ret;
    }

    /* Tell fw_cfg to notify the BIOS to reserve the range. */
    ret = e820_add_entry(identity_base, 0x4000, E820_RESERVED);
    if (ret < 0) {
        fprintf(stderr, "e820_add_entry() table is full\n");
        return ret;
    }

    if (object_dynamic_cast(OBJECT(ms), TYPE_X86_MACHINE) &&
        x86_machine_is_smm_enabled(X86_MACHINE(ms))) {
        smram_machine_done.notify = register_smram_listener;
        qemu_add_machine_init_done_notifier(&smram_machine_done);
    }

    if (object_dynamic_cast(OBJECT(ms), TYPE_X86_MACHINE)) {
        X86MachineState *x86ms = X86_MACHINE(ms);

        if (x86ms->bus_lock_ratelimit > 0) {
            ratelimit_init(&bus_lock_ratelimit_ctrl);
            ratelimit_set_speed(&bus_lock_ratelimit_ctrl,
                                x86ms->bus_lock_ratelimit, BUS_LOCK_SLICE_TIME);
        }
    }

    return 0;
}
