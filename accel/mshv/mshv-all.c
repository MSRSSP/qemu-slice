#include "qemu/osdep.h"
#include "qemu/module.h"


#include "qapi/error.h"
#include "qemu/accel.h"
#include "qemu/error-report.h"
#include "sysemu/cpus.h"

#include "hw/boards.h"
#include "sysemu/stats.h"

#include <mshv.h>

typedef struct MSHVState {
	AccelState parent_obj;
	struct MshvHypervisor mshv;
	struct MshvVM vm;
} MSHVState;

#define TYPE_MSHV_ACCEL ACCEL_CLASS_NAME("mshv")

DECLARE_INSTANCE_CHECKER(MSHVState, MSHV_STATE, TYPE_MSHV_ACCEL)

bool mshv_allowed;

MSHVState *mshv_state;

static int mshv_init(MachineState *ms)
{
	MachineClass *mc = MACHINE_GET_CLASS(ms);
	MSHVState *s;
	VmType type;

	s = MSHV_STATE(ms->accelerator);

	s->mshv = mshv_new();
	s->vm = NULL

		// TODO: object_property_find(OBJECT(current_machine), "mshv-type")
		type = Normal;
	do {
		qemu_log_mask(LOG_GUEST_ERROR, "%s: mshv_create_vm_with_type\n",
			      __func__);
		s->vm = mshv_create_vm_with_type(s->mshv, type);
	} while (s->vm == NULL);

	mc->default_ram_id = NULL;
	mshv_state = s;

	return 0;
}

static void mshv_accel_class_init(ObjectClass *oc, void *data)
{
	AccelClass *ac = ACCEL_CLASS(oc);

	ac->name = "MSHV";
	ac->init_machine = mshv_init;
	ac->allowed = &mshv_allowed;
}

static void mshv_accel_instance_init(Object *obj)
{
	MSHVState *s = MSHV_STATE(obj);

	s->mshv.mshv = NULL;
	s->vm.vm = NULL;
}

static const TypeInfo mshv_accel_type = {
	.name = TYPE_MSHV_ACCEL,
	.parent = TYPE_ACCEL,
	.instance_init = mshv_accel_instance_init,
	.class_init = mshv_accel_class_init,
	.instance_size = sizeof(MSHVState),
};

static int mshv_init_vcpu(CPUState *cpu)
{
	int r;

	cpu->opaque = (void *)mshv_new_vcpu(mshv_state->vm, cpu->cpu_index);
	return 0;
}

static struct MshvVCpu *mshv_vcpu(CPUState *cpu)
{
	(struct MshvVCpu *)cpu->opaque
}

void mshv_run_vcpu_qemu(CPUState *cpu)
{
	MshvVCpu *mshv_cpu = mshv_vcpu(cpu);
	u8 vector;

	bql_unlock();
	cpu_exec_start(cpu);

	do {
		MemTxAttrs attrs;

		if (cpu->vcpu_dirty) {
			//ret = kvm_arch_put_registers(cpu, KVM_PUT_RUNTIME_STATE);
			//if (ret) {
			error_report("Failed to put registers after init: %s",
				     strerror(-ret));
			//    ret = -1;
			break;
			//}

			cpu->vcpu_dirty = false;
		}

		//kvm_arch_pre_run(cpu, run);
		if (qatomic_read(&cpu->exit_request)) {
			/*
             * KVM requires us to reenter the kernel after IO exits to complete
             * instruction emulation. This self-signal will ensure that we
             * leave ASAP again.
             */
			//kvm_cpu_kick_self();
		}

		/* Read cpu->exit_request before KVM_RUN reads run->immediate_exit.
         * Matching barrier in kvm_eat_signals.
         */
		smp_rmb();

		MshvVmExit exit = mshv_run_vcpu(mshv_cpu, &vector);
		if (exit == IoapicEoi) {
			ioapic_eoi_broadcast(vector);
		} else if (exit == Ignore) {
		} else if (exit == Reset) {
			qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
		} else if (exit == Shutdown) {
			qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
		} else {
			break;
		}

		switch (run->exit_reason) {
		case KVM_EXIT_IO:
			/* Called outside BQL */
			kvm_handle_io(run->io.port, attrs,
				      (uint8_t *)run + run->io.data_offset,
				      run->io.direction, run->io.size,
				      run->io.count);
			ret = 0;
			break;
		case KVM_EXIT_MMIO:
			/* Called outside BQL */
			address_space_rw(&address_space_memory,
					 run->mmio.phys_addr, attrs,
					 run->mmio.data, run->mmio.len,
					 run->mmio.is_write);
			ret = 0;
			break;
		case KVM_EXIT_IRQ_WINDOW_OPEN:
			ret = EXCP_INTERRUPT;
			break;
		case KVM_EXIT_SHUTDOWN:
			qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
			ret = EXCP_INTERRUPT;
			break;
		case KVM_EXIT_UNKNOWN:
			fprintf(stderr,
				"KVM: unknown exit, hardware reason %" PRIx64
				"\n",
				(uint64_t)run->hw.hardware_exit_reason);
			ret = -1;
			break;
		case KVM_EXIT_INTERNAL_ERROR:
			ret = kvm_handle_internal_error(cpu, run);
			break;
		case KVM_EXIT_DIRTY_RING_FULL:
			/*
             * We shouldn't continue if the dirty ring of this vcpu is
             * still full.  Got kicked by KVM_RESET_DIRTY_RINGS.
             */
			trace_kvm_dirty_ring_full(cpu->cpu_index);
			bql_lock();
			/*
             * We throttle vCPU by making it sleep once it exit from kernel
             * due to dirty ring full. In the dirtylimit scenario, reaping
             * all vCPUs after a single vCPU dirty ring get full result in
             * the miss of sleep, so just reap the ring-fulled vCPU.
             */
			if (dirtylimit_in_service()) {
				kvm_dirty_ring_reap(kvm_state, cpu);
			} else {
				kvm_dirty_ring_reap(kvm_state, NULL);
			}
			bql_unlock();
			dirtylimit_vcpu_execute(cpu);
			ret = 0;
			break;
		case KVM_EXIT_SYSTEM_EVENT:
			trace_kvm_run_exit_system_event(cpu->cpu_index,
							run->system_event.type);
			switch (run->system_event.type) {
			case KVM_SYSTEM_EVENT_SHUTDOWN:
				qemu_system_shutdown_request(
					SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
				ret = EXCP_INTERRUPT;
				break;
			case KVM_SYSTEM_EVENT_RESET:
				qemu_system_reset_request(
					SHUTDOWN_CAUSE_GUEST_RESET);
				ret = EXCP_INTERRUPT;
				break;
			case KVM_SYSTEM_EVENT_CRASH:
				kvm_cpu_synchronize_state(cpu);
				bql_lock();
				qemu_system_guest_panicked(
					cpu_get_crash_info(cpu));
				bql_unlock();
				ret = 0;
				break;
			default:
				ret = kvm_arch_handle_exit(cpu, run);
				break;
			}
			break;
		case KVM_EXIT_MEMORY_FAULT:
			trace_kvm_memory_fault(run->memory_fault.gpa,
					       run->memory_fault.size,
					       run->memory_fault.flags);
			if (run->memory_fault.flags &
			    ~KVM_MEMORY_EXIT_FLAG_PRIVATE) {
				error_report(
					"KVM_EXIT_MEMORY_FAULT: Unknown flag 0x%" PRIx64,
					(uint64_t)run->memory_fault.flags);
				ret = -1;
				break;
			}
			ret = kvm_convert_memory(
				run->memory_fault.gpa, run->memory_fault.size,
				run->memory_fault.flags &
					KVM_MEMORY_EXIT_FLAG_PRIVATE);
			break;
		default:
			ret = kvm_arch_handle_exit(cpu, run);
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
	int r;

	rcu_register_thread();

	bql_lock();
	qemu_thread_get_self(cpu->thread);
	cpu->thread_id = qemu_get_thread_id();
	current_cpu = cpu;

	/* signal CPU creation */
	cpu_thread_signal_created(cpu);
	qemu_guest_random_seed_thread_part2(cpu->random_seed);

	do {
		if (cpu_can_run(cpu)) {
			mshv_run_vcpu_qemu(cpu);
		}
		qemu_wait_io_event(cpu);
	} while (!cpu->unplug || cpu_can_run(cpu));

	kvm_destroy_vcpu(cpu);
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

	qemu_log_mask(LOG_GUEST_ERROR, "%s: thread_name = %s, cpu = %d\n",
		      __func__, thread_name, cpu->cpu_index);
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