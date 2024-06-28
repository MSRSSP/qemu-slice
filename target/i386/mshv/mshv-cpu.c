#include "qemu/osdep.h"

#include "cpu.h"

#include "mshv.h"
#include <linux/kvm.h>
#include "sysemu/mshv_int.h"

inline static MshvVcpuC *mshv_vcpu(CPUState *cpu)
{
    return (MshvVcpuC *)cpu->opaque;
}

static void set_seg(struct SegmentRegisterC *lhs, const SegmentCache *rhs)
{
    unsigned flags = rhs->flags;
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type_ = (flags >> DESC_TYPE_SHIFT) & 15;
    lhs->present = (flags & DESC_P_MASK) != 0;
    lhs->dpl = (flags >> DESC_DPL_SHIFT) & 3;
    lhs->db = (flags >> DESC_B_SHIFT) & 1;
    lhs->s = (flags & DESC_S_MASK) != 0;
    lhs->l = (flags >> DESC_L_SHIFT) & 1;
    lhs->g = (flags & DESC_G_MASK) != 0;
    lhs->avl = (flags & DESC_AVL_MASK) != 0;
    lhs->unusable = !lhs->present;
}

static void get_seg(SegmentCache *lhs, const struct SegmentRegisterC *rhs)
{
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->flags = (rhs->type_ << DESC_TYPE_SHIFT) |
                 ((rhs->present && !rhs->unusable) * DESC_P_MASK) |
                 (rhs->dpl << DESC_DPL_SHIFT) | (rhs->db << DESC_B_SHIFT) |
                 (rhs->s * DESC_S_MASK) | (rhs->l << DESC_L_SHIFT) |
                 (rhs->g * DESC_G_MASK) | (rhs->avl * DESC_AVL_MASK);
}

static void getset_seg(struct SegmentRegisterC *lhs, SegmentCache *rhs,
                       bool set)
{
    if (set) {
        set_seg(lhs, (const SegmentCache *)rhs);
    } else {
        get_seg(rhs, (const struct SegmentRegisterC *)lhs);
    }
}

static void getput_reg(uint64_t *reg, target_ulong *qemu_reg, bool set)
{
    if (set) {
        *reg = *qemu_reg;
    } else {
        *qemu_reg = *reg;
    }
}

static int mshv_getput_regs(MshvState *mshv_state, CPUState *cpu, bool set)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    StandardRegistersC regs;
    SpecialRegistersC sregs;
    FpuStateC fpu;
    int ret = 0;

    if (!set) {
        mshv_get_vcpu(mshv_vcpu(cpu), &regs, &sregs, &fpu);
    }

    getput_reg(&regs.rax, &env->regs[R_EAX], set);
    getput_reg(&regs.rbx, &env->regs[R_EBX], set);
    getput_reg(&regs.rcx, &env->regs[R_ECX], set);
    getput_reg(&regs.rdx, &env->regs[R_EDX], set);
    getput_reg(&regs.rsi, &env->regs[R_ESI], set);
    getput_reg(&regs.rdi, &env->regs[R_EDI], set);
    getput_reg(&regs.rsp, &env->regs[R_ESP], set);
    getput_reg(&regs.rbp, &env->regs[R_EBP], set);
    getput_reg(&regs.rflags, &env->eflags, set);
    getput_reg(&regs.rip, &env->eip, set);

    getset_seg(&sregs.cs, &env->segs[R_CS], set);
    getset_seg(&sregs.ds, &env->segs[R_DS], set);
    getset_seg(&sregs.es, &env->segs[R_ES], set);
    getset_seg(&sregs.fs, &env->segs[R_FS], set);
    getset_seg(&sregs.gs, &env->segs[R_GS], set);
    getset_seg(&sregs.ss, &env->segs[R_SS], set);

    sregs.idt.limit = env->idt.limit;
    sregs.idt.base = env->idt.base;
    sregs.gdt.limit = env->gdt.limit;
    sregs.gdt.base = env->gdt.base;

    getput_reg(&sregs.cr0, &env->cr[0], set);
    getput_reg(&sregs.cr2, &env->cr[2], set);
    getput_reg(&sregs.cr3, &env->cr[3], set);
    getput_reg(&sregs.cr4, &env->cr[4], set);

    getput_reg(&sregs.efer, &env->efer, set);

    if (set) {
        sregs.cr8 = cpu_get_apic_tpr(x86cpu->apic_state);
        sregs.apic_base = cpu_get_apic_base(x86cpu->apic_state);
        memset(&sregs.interrupt_bitmap, 0, sizeof(sregs.interrupt_bitmap));
        memset(&fpu, 0, sizeof(fpu));
        mshv_configure_vcpu(
            mshv_state->mshv, mshv_vcpu(cpu), cpu->cpu_index,
            IS_AMD_CPU(env) ? AMD : (IS_INTEL_CPU(env) ? Intel : Unknown),
            env->nr_dies, cpu->nr_cores / env->nr_dies, cpu->nr_threads, &regs,
            &sregs, env->xcr0, &fpu);
    } else {
        cpu_set_apic_tpr(x86cpu->apic_state, sregs.cr8);
        cpu_set_apic_base(x86cpu->apic_state, sregs.apic_base);
    }

    return ret;
}

int mshv_put_vcpu_events(MshvState *mshv_state, CPUState *cpu);

int mshv_put_vcpu_events(MshvState *mshv_state, CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;

    if (env->nmi_injected) {
        mshv_debug();
        mshv_log("mshv_nmi\n");
        mshv_nmi(mshv_vcpu(cpu));
    }

    return 0;
}

#define MSR_ENTRIES_COUNT 64
static void mshv_msr_buf_alloc(X86CPU *cpu)
{
    u_int64_t size = sizeof(uint64_t) + sizeof(MsrEntryC) * MSR_ENTRIES_COUNT;
    cpu->kvm_msr_buf = g_malloc0(size);
    memset(cpu->kvm_msr_buf, 0, size);
    cpu->kvm_msr_buf->nmsrs = 0;
}

static MsrEntryC *mshv_msr_entry_add(X86CPU *cpu, uint32_t index,
                                     uint64_t value)
{
    struct kvm_msrs *msrs = cpu->kvm_msr_buf;
    struct MsrEntryC *entry = (MsrEntryC *)&msrs->entries[msrs->nmsrs];

    assert(sizeof(MsrEntryC) == sizeof(struct kvm_msr_entry));
    assert(msrs->nmsrs < MSR_ENTRIES_COUNT);

    entry->index = index;
    entry->resvd = 0;
    entry->data = value;
    msrs->nmsrs++;

    return (MsrEntryC *)entry;
}

/*
msr!(msr_index::MSR_IA32_SYSENTER_CS),
msr!(msr_index::MSR_IA32_SYSENTER_ESP),
msr!(msr_index::MSR_IA32_SYSENTER_EIP),
msr!(msr_index::MSR_STAR),
msr!(msr_index::MSR_CSTAR),
msr!(msr_index::MSR_LSTAR),
msr!(msr_index::MSR_KERNEL_GS_BASE),
msr!(msr_index::MSR_SYSCALL_MASK),
msr_data!(msr_index::MSR_MTRRdefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
*/
static int mshv_put_msrs(CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    mshv_msr_buf_alloc(x86cpu);
    mshv_msr_entry_add(x86cpu, MSR_IA32_SYSENTER_CS, env->sysenter_cs);
    mshv_msr_entry_add(x86cpu, MSR_IA32_SYSENTER_ESP, env->sysenter_esp);
    mshv_msr_entry_add(x86cpu, MSR_IA32_SYSENTER_EIP, env->sysenter_eip);
    mshv_msr_entry_add(x86cpu, MSR_PAT, env->pat);
    mshv_msr_entry_add(x86cpu, MSR_STAR, env->star);
    mshv_msr_entry_add(x86cpu, MSR_CSTAR, env->cstar);
    mshv_msr_entry_add(x86cpu, MSR_LSTAR, env->lstar);
    mshv_msr_entry_add(x86cpu, MSR_KERNELGSBASE, env->kernelgsbase);
    mshv_msr_entry_add(x86cpu, MSR_FMASK, env->fmask);
    mshv_msr_entry_add(x86cpu, MSR_MTRRdefType, env->mtrr_deftype);
    /*mshv_msr_entry_add(x86cpu, MSR_VM_HSAVE_PA, env->vm_hsave);
    mshv_msr_entry_add(x86cpu, MSR_TSC_AUX, env->tsc_aux);
    mshv_msr_entry_add(x86cpu, MSR_TSC_ADJUST, env->tsc_adjust);
    mshv_msr_entry_add(x86cpu, MSR_IA32_SMBASE, env->smbase);
    msrs = mshv_msr_entry_add(x86cpu, MSR_IA32_SPEC_CTRL, env->spec_ctrl);*/
    mshv_configure_msr(mshv_vcpu(cpu),
                       (MsrEntryC *)&x86cpu->kvm_msr_buf->entries[0],
                       (uint32_t)x86cpu->kvm_msr_buf->nmsrs);

    return 0;
}

int mshv_arch_put_registers(MshvState *mshv_state, CPUState *cpu)
{
    int ret = 0;

    ret = mshv_getput_regs(mshv_state, cpu, true);
    if (ret) {
        return ret;
    }

    ret = mshv_put_msrs(cpu);
    if (ret) {
        return ret;
    }

    ret = mshv_put_vcpu_events(mshv_state, cpu);
    if (ret) {
        return ret;
    }

    return ret;
}

int mshv_arch_get_registers(MshvState *mshv_state, CPUState *cpu);

int mshv_arch_get_registers(MshvState *mshv_state, CPUState *cpu)
{
    return mshv_getput_regs(mshv_state, cpu, true);
}