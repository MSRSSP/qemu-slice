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

#include <mshv.h>

typedef struct MshvState {
    AccelState parent_obj;
    MshvHypervisorC *mshv;
    MshvVmC *vm;
} MshvState;

#define TYPE_MSHV_ACCEL ACCEL_CLASS_NAME("mshv")

DECLARE_INSTANCE_CHECKER(MshvState, MSHV_STATE, TYPE_MSHV_ACCEL)

bool mshv_allowed;

MshvState *mshv_state;

static void mshv_set_dirty_tracking(MemoryRegionSection *section, bool on)
{
    qemu_log_mask(LOG_GUEST_ERROR, "%s: unimplemented\n", __func__);
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

static void mshv_region_add(MemoryListener *listener,
                            MemoryRegionSection *section)
{
    qemu_log_mask(LOG_GUEST_ERROR, "%s: unimplemented\n", __func__);
}

static void mshv_region_del(MemoryListener *listener,
                            MemoryRegionSection *section)
{
    qemu_log_mask(LOG_GUEST_ERROR, "%s: unimplemented\n", __func__);
}

static MemoryListener mshv_memory_listener = {
    .name = "mshv",
    .priority = MEMORY_LISTENER_PRIORITY_ACCEL,
    .region_add = mshv_region_add,
    .region_del = mshv_region_del,
    .log_start = mshv_log_start,
    .log_stop = mshv_log_stop,
    .log_sync = mshv_log_sync,
};


static void mshv_memory_listener_register(AddressSpace *as)
{
    memory_listener_register(&mshv_memory_listener, as);
}

static int mshv_init(MachineState *ms)
{
    MachineClass *mc = MACHINE_GET_CLASS(ms);
    MshvState *s;
    uint64_t vm_type;

    qemu_log_mask(LOG_GUEST_ERROR, "%s\n", __func__);

    s = MSHV_STATE(ms->accelerator);

    s->mshv = mshv_new();
    s->vm = NULL;

    // TODO: object_property_find(OBJECT(current_machine), "mshv-type")
    vm_type = 0;
    do {
        qemu_log_mask(LOG_GUEST_ERROR, "%s\n", __func__);
        s->vm = mshv_create_vm_with_type(s->mshv, vm_type);
    } while (s->vm == NULL);

    mc->default_ram_id = NULL;

    // register memory listener
    mshv_memory_listener_register(&address_space_memory);

    mshv_state = s;
    return 0;
}

static void mshv_accel_class_init(ObjectClass *oc, void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    qemu_log_mask(LOG_GUEST_ERROR, "%s\n", __func__);

    ac->name = "MSHV";
    ac->init_machine = mshv_init;
    ac->allowed = &mshv_allowed;
}

static void mshv_accel_instance_init(Object *obj)
{
    MshvState *s = MSHV_STATE(obj);
    qemu_log_mask(LOG_GUEST_ERROR, "%s\n", __func__);

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

    qemu_log_mask(LOG_GUEST_ERROR, "%s\n", __func__);
    do {
        if (cpu->vcpu_dirty) {
            // ret = kvm_arch_put_registers(cpu, KVM_PUT_RUNTIME_STATE);
            // if (ret) {
            error_report("Failed to put registers after init: %s",
                         strerror(-ret));
            ret = -1;
            break;
            //}

            cpu->vcpu_dirty = false;
        }

        // kvm_arch_pre_run(cpu, run);
        if (qatomic_read(&cpu->exit_request)) {
            /*
             * KVM requires us to reenter the kernel after IO exits to complete
             * instruction emulation. This self-signal will ensure that we
             * leave ASAP again.
             */
            // kvm_cpu_kick_self();
        }

        /* Read cpu->exit_request before KVM_RUN reads run->immediate_exit.
         * Matching barrier in kvm_eat_signals.
         */
        smp_rmb();

        MshvVmExit exit = mshv_run_vcpu(mshv_cpu, &vector);
        switch (exit) {
        case IoapicEoi:
            ioapic_eoi_broadcast(vector);
            break;
        case Reset:
        case Shutdown:
            qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
            ret = EXCP_INTERRUPT;
            break;
        case Ignore:
            break;
        default:
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
static void *mshv_vcpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;

    rcu_register_thread();

    bql_lock();
    qemu_thread_get_self(cpu->thread);
    cpu->thread_id = qemu_get_thread_id();
    current_cpu = cpu;
    mshv_init_vcpu(cpu);

    /* signal CPU creation */
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    qemu_log_mask(LOG_GUEST_ERROR, "%s:%d: cpu = %d\n", __func__, __LINE__,
                  cpu->cpu_index);
    do {
        if (cpu_can_run(cpu)) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s:%d: cpu = %d\n", __func__,
                          __LINE__, cpu->cpu_index);
            mshv_run_vcpu_qemu(cpu);
        }
        qemu_log_mask(LOG_GUEST_ERROR, "%s:%d: cpu = %d\n", __func__, __LINE__,
                      cpu->cpu_index);
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

    qemu_log_mask(LOG_GUEST_ERROR, "%s: thread_name = %s, cpu = %d\n", __func__,
                  thread_name, cpu->cpu_index);
    qemu_thread_create(cpu->thread, thread_name, mshv_vcpu_thread_fn, cpu,
                       QEMU_THREAD_JOINABLE);
}

static void mshv_accel_ops_class_init(ObjectClass *oc, void *data)
{
    AccelOpsClass *ops = ACCEL_OPS_CLASS(oc);

    ops->create_vcpu_thread = mshv_start_vcpu_thread;
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