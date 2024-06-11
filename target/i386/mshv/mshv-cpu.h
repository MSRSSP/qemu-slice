
#ifndef KVM_CPU_H
#define KVM_CPU_H

#ifdef CONFIG_MSHV

int mshv_arch_put_registers(CPUState *cpu);

#endif

#endif