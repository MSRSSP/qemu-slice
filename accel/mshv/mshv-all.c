#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/module.h"

#include "exec/address-spaces.h"
#include "hw/i386/x86.h" //ioapic_eoi_broadcast
#include "qemu/accel.h"
#include "qemu/guest-random.h"
#include "qemu/log.h"
#include "sysemu/cpus.h"
#include "sysemu/runstate.h" //vm_stop
#include "sysemu/stats.h"
#include "sysemu/accel-blocker.h"
#include "sysemu/mshv_int.h"

#include "target/i386/mshv/mshv-cpu.h"

#include <mshv.h>

static QemuMutex mml_slots_lock;

#define mshv_slots_lock()   qemu_mutex_lock(&mml_slots_lock)
#define mshv_slots_unlock() qemu_mutex_unlock(&mml_slots_lock)

#define TYPE_MSHV_ACCEL ACCEL_CLASS_NAME("mshv")

DECLARE_INSTANCE_CHECKER(MshvState, MSHV_STATE, TYPE_MSHV_ACCEL)

bool mshv_allowed;

MshvState *mshv_state;

static MshvMemoryRegion *mshv_lookup_matching_slot(MshvMemoryListener *mml,
                                                   hwaddr start_addr,
                                                   hwaddr size)
{
    MshvState *s = mshv_state;
    int i;

    for (i = 0; i < s->nr_slot; i++) {
        MshvMemoryRegion *mem = &mml->slots[i];

        if (start_addr == mem->guest_phys_addr && size == mem->memory_size) {
            return mem;
        }
    }

    return NULL;
}

static void mshv_set_dirty_tracking(MemoryRegionSection *section, bool on)
{
    mshv_todo();
}

static void mshv_log_start(MemoryListener *listener,
                           MemoryRegionSection *section, int old, int new)
{
    if (old != 0) {
        return;
    }

    mshv_set_dirty_tracking(section, 1);
}

static void mshv_log_stop(MemoryListener *listener,
                          MemoryRegionSection *section, int old, int new)
{
    if (new != 0) {
        return;
    }

    mshv_set_dirty_tracking(section, 0);
}

static void mshv_log_sync(MemoryListener *listener,
                          MemoryRegionSection *section)
{
    /*
     * sync of dirty pages is handled elsewhere; just make sure we keep
     * tracking the region.
     */
    mshv_set_dirty_tracking(section, 1);
}

static MshvMemoryRegion *mshv_alloc_slot(MshvMemoryListener *mml)
{
    int i = 0;
    for (i = 0; i < mshv_state->nr_slot; i++) {
        if (mml->slots[i].memory_size == 0) {
            return &mml->slots[i];
        }
    }
    return NULL;
}

static bool do_mshv_set_memory(MshvMemoryListener *mml, MshvMemoryRegion *mem,
                               bool add)
{
    mshv_debug();
    if (add) {
        return mshv_add_mem(mshv_state->vm, mem);
    } else {
        if (mem != NULL) {
            mem->memory_size = 0;
            return mshv_remove_mem(mshv_state->vm, mem);
        }
    }
    return false;
}

static void mshv_set_phys_mem(MshvMemoryListener *mml,
                              MemoryRegionSection *section, bool add,
                              const char *name)
{
    MemoryRegion *area = section->mr;
    bool writable = !area->readonly && !area->rom_device;
    uint64_t page_size = qemu_real_host_page_size();
    uint64_t mem_size = int128_get64(section->size);
    uint64_t start_addr;
    MshvMemoryRegion *mem;
    hwaddr as_offset = section->offset_within_address_space;
    hwaddr region_offset = section->offset_within_region;

    mshv_log("(todo) %s(%s): mem[offset: %lx size: %lx]: %s\n", __func__, name,
             section->offset_within_address_space, mem_size,
             area->readonly ? "ronly" : "rw");
    if (!memory_region_is_ram(area)) {
        if (writable) {
            mshv_debug();
            return;
        } else if (!memory_region_is_romd(area)) {
            /*
             * If the memory device is not in romd_mode, then we actually want
             * to remove the hvf memory slot so all accesses will trap.
             */
            add = false;
        }
    }
    mshv_debug();

    if (!QEMU_IS_ALIGNED(int128_get64(section->size), page_size) ||
        !QEMU_IS_ALIGNED(section->offset_within_address_space, page_size)) {
        /* Not page aligned, so we can not map as RAM */
        add = false;
    }
    mshv_debug();
    start_addr =
        (uint64_t)memory_region_get_ram_ptr(area) + (uint64_t)region_offset;

    if (!add) {
        mem = mshv_lookup_matching_slot(mml, start_addr, mem_size);
        if (!mem) {
            mshv_log("Mem not found\n");
            abort();
        }
        if (do_mshv_set_memory(mml, mem, false)) {
            mshv_log("Failed to remove mem\n");
            abort();
        }
        mshv_debug();
        return;
    }

    mem = mshv_alloc_slot(mml);
    mem->guest_phys_addr = start_addr;
    mem->memory_size = mem_size;
    mem->readonly = !writable;
    mem->userspace_addr = as_offset;
    if (do_mshv_set_memory(mml, mem, true)) {
        mshv_log("Failed to add mem\n");
        abort();
    }

    mshv_log("%s (%s): mem(%lx)[offset: %lx size: %lx]: %s\n", __func__, name,
             add ? start_addr : 0, as_offset, mem_size,
             mem->readonly ? "ronly" : "rw");
}

static void mshv_region_add(MemoryListener *listener,
                            MemoryRegionSection *section)
{
    MshvMemoryListener *mml =
        container_of(listener, MshvMemoryListener, listener);
    MshvMemoryUpdate *update;

    update = g_new0(MshvMemoryUpdate, 1);
    update->section = *section;
    mshv_log("%s: mem[offset: %lx size: %lx]\n", __func__,
             section->offset_within_address_space, int128_get64(section->size));
    QSIMPLEQ_INSERT_TAIL(&mml->transaction_add, update, next);
}

static void mshv_region_commit(MemoryListener *listener)
{
    MshvMemoryListener *mml =
        container_of(listener, MshvMemoryListener, listener);
    MshvMemoryUpdate *u1, *u2;
    bool need_inhibit = false;

    if (QSIMPLEQ_EMPTY(&mml->transaction_add) &&
        QSIMPLEQ_EMPTY(&mml->transaction_del)) {
        return;
    }

    /*
     * We have to be careful when regions to add overlap with ranges to remove.
     * We have to simulate atomic KVM memslot updates by making sure no ioctl()
     * is currently active.
     *
     * The lists are order by addresses, so it's easy to find overlaps.
     */
    u1 = QSIMPLEQ_FIRST(&mml->transaction_del);
    u2 = QSIMPLEQ_FIRST(&mml->transaction_add);
    while (u1 && u2) {
        Range r1, r2;

        range_init_nofail(&r1, u1->section.offset_within_address_space,
                          int128_get64(u1->section.size));
        range_init_nofail(&r2, u2->section.offset_within_address_space,
                          int128_get64(u2->section.size));

        if (range_overlaps_range(&r1, &r2)) {
            need_inhibit = true;
            break;
        }
        if (range_lob(&r1) < range_lob(&r2)) {
            u1 = QSIMPLEQ_NEXT(u1, next);
        } else {
            u2 = QSIMPLEQ_NEXT(u2, next);
        }
    }

    mshv_slots_lock();
    if (need_inhibit) {
        accel_ioctl_inhibit_begin();
    }

    /* Remove all memslots before adding the new ones. */
    while (!QSIMPLEQ_EMPTY(&mml->transaction_del)) {
        u1 = QSIMPLEQ_FIRST(&mml->transaction_del);
        QSIMPLEQ_REMOVE_HEAD(&mml->transaction_del, next);

        mshv_set_phys_mem(mml, &u1->section, false, "remove");
        memory_region_unref(u1->section.mr);

        g_free(u1);
    }
    while (!QSIMPLEQ_EMPTY(&mml->transaction_add)) {
        u1 = QSIMPLEQ_FIRST(&mml->transaction_add);
        QSIMPLEQ_REMOVE_HEAD(&mml->transaction_add, next);

        memory_region_ref(u1->section.mr);
        mshv_set_phys_mem(mml, &u1->section, true, "add");

        g_free(u1);
    }

    mshv_debug();

    if (need_inhibit) {
        mshv_debug();
        accel_ioctl_inhibit_end();
        mshv_debug();
    }
    mshv_slots_unlock();

    mshv_debug();
}

static void mshv_region_del(MemoryListener *listener,
                            MemoryRegionSection *section)
{
    MshvMemoryListener *mml =
        container_of(listener, MshvMemoryListener, listener);
    MshvMemoryUpdate *update;

    update = g_new0(MshvMemoryUpdate, 1);
    update->section = *section;
    mshv_log("%s: mem[offset: %lx size: %lx]\n", __func__,
             section->offset_within_address_space, int128_get64(section->size));
    QSIMPLEQ_INSERT_TAIL(&mml->transaction_del, update, next);
}

static void mshv_coalesce_mmio_region(MemoryListener *listener,
                                      MemoryRegionSection *section,
                                      hwaddr start, hwaddr size)
{
    mshv_debug();
    mshv_log("%s: mmio[offset: %lx size: %lx]: [%lx %lx]\n", __func__,
             section->offset_within_address_space, int128_get64(section->size),
             start, size);
}

static void mshv_mem_ioeventfd_add(MemoryListener *listener,
                                   MemoryRegionSection *section,
                                   bool match_data, uint64_t data,
                                   EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;
    bool is_64 = int128_get64(section->size) > 4;

    mshv_log("%s: io_io[offset: %lx size: %lx]: %lx\n", __func__,
             section->offset_within_address_space, int128_get64(section->size),
             data);
    r = mshv_register_ioevent(mshv_state->vm, fd, true,
                              section->offset_within_address_space, data, is_64,
                              match_data);
    if (r < 0) {
        fprintf(stderr, "%s: error adding ioeventfd: %s (%d)\n", __func__,
                strerror(-r), -r);
        abort();
    }
}

static void mshv_mem_ioeventfd_del(MemoryListener *listener,
                                   MemoryRegionSection *section,
                                   bool match_data, uint64_t data,
                                   EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;
    bool is_64 = int128_get64(section->size) > 4;

    mshv_log("%s: io_io[offset: %lx size: %lx]: %lx\n", __func__,
             section->offset_within_address_space, int128_get64(section->size),
             data);
    r = mshv_register_ioevent(mshv_state->vm, fd, true,
                              section->offset_within_address_space, data, is_64,
                              match_data);
    if (r < 0) {
        fprintf(stderr, "%s: error adding ioeventfd: %s (%d)\n", __func__,
                strerror(-r), -r);
        abort();
    }
}

static void mshv_io_ioeventfd_add(MemoryListener *listener,
                                  MemoryRegionSection *section, bool match_data,
                                  uint64_t data, EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;
    bool is_64 = int128_get64(section->size) > 4 ? true : false;

    mshv_log("%s: io_io[offset: %lx size: %lx]: %lx\n", __func__,
             section->offset_within_address_space, int128_get64(section->size),
             data);
    r = mshv_register_ioevent(mshv_state->vm, fd, false,
                              section->offset_within_address_space, data, is_64,
                              match_data);
    if (r < 0) {
        fprintf(stderr, "%s: error adding ioeventfd: %s (%d)\n", __func__,
                strerror(-r), -r);
        abort();
    }
}

static void mshv_io_ioeventfd_del(MemoryListener *listener,
                                  MemoryRegionSection *section, bool match_data,
                                  uint64_t data, EventNotifier *e)
{
    int fd = event_notifier_get_fd(e);
    int r;

    mshv_log("%s: io_io[offset: %lx size: %lx]: %lx\n", __func__,
             section->offset_within_address_space, int128_get64(section->size),
             data);
    r = mshv_unregister_ioevent(mshv_state->vm, fd, false,
                                section->offset_within_address_space);
    if (r < 0) {
        fprintf(stderr, "%s: error adding ioeventfd: %s (%d)\n", __func__,
                strerror(-r), -r);
        abort();
    }
}

static MemoryListener mshv_memory_listener = {
    .name = "mshv",
    .priority = MEMORY_LISTENER_PRIORITY_ACCEL,
    .region_add = mshv_region_add,
    .region_del = mshv_region_del,
    .commit = mshv_region_commit,
    .eventfd_add = mshv_mem_ioeventfd_add,
    .eventfd_del = mshv_mem_ioeventfd_del,
    .coalesced_io_add = mshv_coalesce_mmio_region,
    .log_start = mshv_log_start,
    .log_stop = mshv_log_stop,
    .log_sync = mshv_log_sync,
};

static MemoryListener mshv_io_listener = {
    .name = "mshv",
    .priority = MEMORY_LISTENER_PRIORITY_DEV_BACKEND,
    .eventfd_add = mshv_io_ioeventfd_add,
    .eventfd_del = mshv_io_ioeventfd_del,
    .coalesced_io_add = mshv_coalesce_mmio_region,
};

void mshv_memory_listener_register(MshvState *s, MshvMemoryListener *mml,
                                          AddressSpace *as, int as_id,
                                          const char *name)
{
    int i;

    QSIMPLEQ_INIT(&mml->transaction_add);
    QSIMPLEQ_INIT(&mml->transaction_del);
    mml->listener = mshv_memory_listener;
    memory_listener_register(&mml->listener, as);
    for (i = 0; i < s->nr_as; ++i) {
        if (!s->as[i].as) {
            s->as[i].as = as;
            s->as[i].ml = mml;
            break;
        }
    }
}

static int mshv_init(MachineState *ms)
{
    MachineClass *mc = MACHINE_GET_CLASS(ms);
    MshvState *s;
    uint64_t vm_type;

    mshv_debug();

    qemu_mutex_init(&mml_slots_lock);
    s = MSHV_STATE(ms->accelerator);

    accel_blocker_init();

    s->mshv = mshv_new();
    s->vm = NULL;

    // TODO: object_property_find(OBJECT(current_machine), "mshv-type")
    vm_type = 0;
    do {
        mshv_debug();
        s->vm = mshv_create_vm_with_type(s->mshv, vm_type);
    } while (s->vm == NULL);

    mc->default_ram_id = NULL;

    s->nr_slot = 32;
    s->nr_as = 2;
    s->as = g_new0(struct MshvAs, s->nr_as);

    mshv_state = s;
    mshv_arch_init(ms, s);

    // register memory listener
    mshv_memory_listener_register(s, &s->memory_listener, &address_space_memory,
                                  0, "mshv-memory");
    memory_listener_register(&mshv_io_listener, &address_space_io);

    return 0;
}

static bool mshv_accel_has_memory(MachineState *ms, AddressSpace *as,
                                  hwaddr start_addr, hwaddr size)
{
    MshvState *s = mshv_state;
    int i;

    for (i = 0; i < s->nr_as; ++i) {
        if (s->as[i].as == as && s->as[i].ml) {
            return NULL !=
                   mshv_lookup_matching_slot(s->as[i].ml, start_addr, size);
        }
    }

    return false;
}

static void mshv_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    mshv_debug();

    ac->name = "MSHV";
    ac->init_machine = mshv_init;
    ac->allowed = &mshv_allowed;
    ac->has_memory = mshv_accel_has_memory;
}

static void mshv_accel_instance_init(Object *obj)
{
    MshvState *s = MSHV_STATE(obj);
    mshv_debug();

    s->mshv = NULL;
    s->vm = NULL;
}

static const TypeInfo mshv_accel_type = {
    .name = TYPE_MSHV_ACCEL,
    .parent = TYPE_ACCEL,
    .instance_init = mshv_accel_instance_init,
    .class_init = mshv_accel_class_init,
    .instance_size = sizeof(MshvState),
};

static int mshv_init_vcpu(CPUState *cpu)
{
    cpu->opaque = (void *)mshv_new_vcpu(mshv_state->vm, cpu->cpu_index);
    cpu->vcpu_dirty = false;

    return 0;
}

static int mshv_destroy_vcpu(CPUState *cpu)
{
    cpu->opaque = NULL;
    return 0;
}

inline static MshvVcpuC *mshv_vcpu(CPUState *cpu)
{
    return (MshvVcpuC *)cpu->opaque;
}

int mshv_run_vcpu_qemu(CPUState *cpu);

int mshv_run_vcpu_qemu(CPUState *cpu)
{
    MshvVcpuC *mshv_cpu = mshv_vcpu(cpu);
    uint8_t vector;
    int ret = 0;

    bql_unlock();
    cpu_exec_start(cpu);

    mshv_debug();
    do {
        if (cpu->vcpu_dirty) {
            ret = mshv_arch_put_registers(cpu);
            break;
            cpu->vcpu_dirty = false;
        }

        if (qatomic_read(&cpu->exit_request)) {
            mshv_debug();
        }

        /* Read cpu->exit_request before KVM_RUN reads run->immediate_exit.
         * Matching barrier in kvm_eat_signals.
         */
        smp_rmb();

        MshvVmExit exit = mshv_run_vcpu(mshv_cpu, &vector);
        switch (exit) {
        case IoapicEoi:
            mshv_log("ioapic_eoi_broadcast %d\n", vector);
            ioapic_eoi_broadcast(vector);
            break;
        case Reset:
        case Shutdown:
            qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
            ret = EXCP_INTERRUPT;
            break;
        case Ignore:
            mshv_log("Ignore\n");
            break;
        default:
            mshv_log("Default\n");
            break;
        }
    } while (ret == 0);

    cpu_exec_end(cpu);
    bql_lock();

    if (ret < 0) {
        cpu_dump_state(cpu, stderr, CPU_DUMP_CODE);
        vm_stop(RUN_STATE_INTERNAL_ERROR);
    }

    qatomic_set(&cpu->exit_request, 0);
    return ret;
}

static void dummy_signal(int sig)
{
    mshv_debug();
}

static int mshv_set_signal_mask(CPUState *cpu, const sigset_t *sigset)
{
    mshv_debug();

    return 0;
}

static void mshv_init_signal(CPUState *cpu)
{
    /* init cpu signals */
    struct sigaction sigact;
    sigset_t set;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = dummy_signal;
    sigaction(SIG_IPI, &sigact, NULL);

    pthread_sigmask(SIG_BLOCK, NULL, &set);
    sigdelset(&set, SIG_IPI);
    mshv_set_signal_mask(cpu, &set);
}

static void *mshv_vcpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;

    rcu_register_thread();

    bql_lock();
    qemu_thread_get_self(cpu->thread);
    cpu->thread_id = qemu_get_thread_id();
    current_cpu = cpu;
    mshv_init_vcpu(cpu);
    mshv_init_signal(cpu);

    /* signal CPU creation */
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    mshv_log("%s:%d: cpu = %d\n", __func__, __LINE__, cpu->cpu_index);
    do {
        if (cpu_can_run(cpu)) {
            mshv_debug();
            mshv_run_vcpu_qemu(cpu);
        }
        mshv_debug();
        qemu_wait_io_event(cpu);
    } while (!cpu->unplug || cpu_can_run(cpu));

    mshv_destroy_vcpu(cpu);
    cpu_thread_signal_destroyed(cpu);
    bql_unlock();
    rcu_unregister_thread();
    return NULL;
}

static void mshv_start_vcpu_thread(CPUState *cpu)
{
    char thread_name[VCPU_THREAD_NAME_SIZE];

    cpu->thread = g_malloc0(sizeof(QemuThread));
    cpu->halt_cond = g_malloc0(sizeof(QemuCond));
    qemu_cond_init(cpu->halt_cond);

    mshv_log("%s: thread_name = %s, cpu = %d\n", __func__, thread_name,
             cpu->cpu_index);
    qemu_thread_create(cpu->thread, thread_name, mshv_vcpu_thread_fn, cpu,
                       QEMU_THREAD_JOINABLE);
}

static void mshv_cpu_synchronize_post_init(CPUState *cpu)
{
    mshv_arch_put_registers(cpu);

    cpu->vcpu_dirty = false;
}

static void do_mshv_cpu_synchronize_pre_loadvm(CPUState *cpu,
                                               run_on_cpu_data arg)
{
    cpu->vcpu_dirty = true;
}

void mshv_cpu_synchronize_pre_loadvm(CPUState *cpu);

void mshv_cpu_synchronize_pre_loadvm(CPUState *cpu)
{
    run_on_cpu(cpu, do_mshv_cpu_synchronize_pre_loadvm, RUN_ON_CPU_NULL);
}

static void mshv_accel_ops_class_init(ObjectClass *oc, void *data)
{
    AccelOpsClass *ops = ACCEL_OPS_CLASS(oc);

    ops->create_vcpu_thread = mshv_start_vcpu_thread;
    ops->synchronize_post_init = mshv_cpu_synchronize_post_init;
    ops->synchronize_pre_loadvm = mshv_cpu_synchronize_pre_loadvm;
}

static const TypeInfo mshv_accel_ops_type = {
    .name = ACCEL_OPS_NAME("mshv"),
    .parent = TYPE_ACCEL_OPS,
    .class_init = mshv_accel_ops_class_init,
    .abstract = true,
};

static void mshv_type_init(void)
{
    type_register_static(&mshv_accel_type);
    type_register_static(&mshv_accel_ops_type);
}

type_init(mshv_type_init);