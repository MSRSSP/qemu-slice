#include "qemu/osdep.h"

#include "cpu.h"

#include "mshv.h"
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

    if (env->nmi_injected && env->nmi_pending) {
        mshv_nmi(mshv_vcpu(cpu));
    }

    return 0;
}

int mshv_arch_put_registers(MshvState *mshv_state, CPUState *cpu)
{
    return mshv_getput_regs(mshv_state, cpu, true);
}

int mshv_arch_get_registers(MshvState *mshv_state, CPUState *cpu);

int mshv_arch_get_registers(MshvState *mshv_state, CPUState *cpu)
{
    return mshv_getput_regs(mshv_state, cpu, true);
}