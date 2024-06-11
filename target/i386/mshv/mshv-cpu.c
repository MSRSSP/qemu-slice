#include "qemu/osdep.h"

#include "cpu.h"

#include "mshv.h"
#include "mshv-cpu.h"

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

int mshv_arch_put_registers(CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    assert(cpu_is_stopped(cpu) || qemu_cpu_is_self(cpu));

    CPUX86State *env = &x86cpu->env;

    StandardRegistersC regs = {
        .rax = env->regs[R_EAX],
        .rbx = env->regs[R_EBX],
        .rcx = env->regs[R_ECX],
        .rdx = env->regs[R_EDX],
        .rsi = env->regs[R_ESI],
        .rdi = env->regs[R_EDI],
        .rsp = env->regs[R_ESP],
        .rbp = env->regs[R_EBP],
        .rflags = env->eflags,
        .rip = env->eip,
    };
    SpecialRegistersC sregs;
    set_seg(&sregs.cs, &env->segs[R_CS]);
    set_seg(&sregs.ds, &env->segs[R_DS]);
    set_seg(&sregs.es, &env->segs[R_ES]);
    set_seg(&sregs.fs, &env->segs[R_FS]);
    set_seg(&sregs.gs, &env->segs[R_GS]);
    set_seg(&sregs.ss, &env->segs[R_SS]);

    sregs.idt.limit = env->idt.limit;
    sregs.idt.base = env->idt.base;
    sregs.gdt.limit = env->gdt.limit;
    sregs.gdt.base = env->gdt.base;

    sregs.cr0 = env->cr[0];
    sregs.cr2 = env->cr[2];
    sregs.cr3 = env->cr[3];
    sregs.cr4 = env->cr[4];

    sregs.cr8 = cpu_get_apic_tpr(x86cpu->apic_state);
    sregs.efer = env->efer;
    sregs.apic_base = cpu_get_apic_base(x86cpu->apic_state);
    memset(&sregs.interrupt_bitmap, 0, sizeof(sregs.interrupt_bitmap));

    FpuStateC fpu;
    memset(&fpu, 0, sizeof(fpu));

    mshv_configure_vcpu(mshv_vcpu(cpu), &regs, &sregs, &fpu);

    return 0;
}