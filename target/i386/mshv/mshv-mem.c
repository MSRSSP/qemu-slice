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

static void register_smram_listener(Notifier *n, void *unused)
{
    mshv_debug();
    MemoryRegion *smram =
        (MemoryRegion *)object_resolve_path("/machine/smram", NULL);
    /* Outer container... */
    memory_region_init(&smram_as_root, OBJECT(mshv_state),
                       "mem-container-smram", ~0ull);
    memory_region_set_enabled(&smram_as_root, true);
    /* ... with two regions inside: normal system memory with low
     * priority, and...
     */
    memory_region_init_alias(&smram_as_mem, OBJECT(mshv_state), "mem-smram",
                             get_system_memory(), 0, ~0ull);
    memory_region_add_subregion_overlap(&smram_as_root, 0, &smram_as_mem, 0);
    memory_region_set_enabled(&smram_as_mem, true);
    if (smram) {
        /* ... SMRAM with higher priority */
        memory_region_add_subregion_overlap(&smram_as_root, 0, smram, 10);
        memory_region_set_enabled(smram, true);
    }
    address_space_init(&smram_address_space, &smram_as_root, "KVM-SMRAM");
    mshv_memory_listener_register(mshv_state, &smram_listener,
                                  &smram_address_space, 1, "kvm-smram");
    mshv_debug();
}

static RateLimit bus_lock_ratelimit_ctrl;
#define BUS_LOCK_SLICE_TIME 1000000000ULL /* ns */

bool mshv_arch_init(MachineState *ms, MshvState *s)
{
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
    smram_machine_done.notify = register_smram_listener;
    qemu_add_machine_init_done_notifier(&smram_machine_done);

    mshv_debug();
    X86MachineState *x86ms = X86_MACHINE(ms);

    if (x86ms->bus_lock_ratelimit > 0) {
        ratelimit_init(&bus_lock_ratelimit_ctrl);
        ratelimit_set_speed(&bus_lock_ratelimit_ctrl,
                            x86ms->bus_lock_ratelimit, BUS_LOCK_SLICE_TIME);
    }
    mshv_debug();
    return 0;
}
