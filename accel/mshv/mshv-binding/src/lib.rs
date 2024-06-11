use std::{ptr::NonNull, sync::Arc};

use hypervisor::arch::x86::{
    DescriptorTable, FpuState, SegmentRegister, SpecialRegisters, StandardRegisters,
};
use hypervisor::{mshv, Hypervisor, Vcpu, Vm};

#[repr(C)]
pub struct MshvVmC;

#[repr(C)]
pub struct MshvHypervisorC;

#[repr(C)]
pub struct MshvVcpuC;

#[repr(C)]
pub struct MshvMemoryMapC;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct StandardRegistersC {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl From<StandardRegistersC> for StandardRegisters {
    fn from(regs: StandardRegistersC) -> Self {
        StandardRegisters {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct SegmentRegisterC {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
}

impl From<SegmentRegisterC> for SegmentRegister {
    fn from(s: SegmentRegisterC) -> Self {
        Self {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            avl: s.avl,
            unusable: s.unusable,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct DescriptorTableC {
    pub base: u64,
    pub limit: u16,
}

impl From<DescriptorTableC> for DescriptorTable {
    fn from(dt: DescriptorTableC) -> Self {
        Self {
            base: dt.base,
            limit: dt.limit,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct SpecialRegistersC {
    pub cs: SegmentRegisterC,
    pub ds: SegmentRegisterC,
    pub es: SegmentRegisterC,
    pub fs: SegmentRegisterC,
    pub gs: SegmentRegisterC,
    pub ss: SegmentRegisterC,
    pub tr: SegmentRegisterC,
    pub ldt: SegmentRegisterC,
    pub gdt: DescriptorTableC,
    pub idt: DescriptorTableC,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4usize],
}

impl From<SpecialRegistersC> for SpecialRegisters {
    fn from(s: SpecialRegistersC) -> Self {
        Self {
            cs: s.cs.into(),
            ds: s.ds.into(),
            es: s.es.into(),
            fs: s.fs.into(),
            gs: s.gs.into(),
            ss: s.ss.into(),
            tr: s.tr.into(),
            ldt: s.ldt.into(),
            gdt: s.gdt.into(),
            idt: s.idt.into(),
            cr0: s.cr0,
            cr2: s.cr2,
            cr3: s.cr3,
            cr4: s.cr4,
            cr8: s.cr8,
            efer: s.efer,
            apic_base: s.apic_base,
            interrupt_bitmap: s.interrupt_bitmap,
        }
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone)]
pub struct FpuStateC {
    pub fpr: [[u8; 16usize]; 8usize],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16usize]; 16usize],
    pub mxcsr: u32,
}

impl From<FpuStateC> for FpuState {
    fn from(s: FpuStateC) -> Self {
        Self {
            fpr: s.fpr,
            fcw: s.fcw,
            fsw: s.fsw,
            ftwx: s.ftwx,
            last_opcode: s.last_opcode,
            last_ip: s.last_ip,
            last_dp: s.last_dp,
            xmm: s.xmm,
            mxcsr: s.mxcsr,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct CpuIdEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub const CPUID_FLAG_VALID_INDEX: u32 = 1;

#[repr(C)]
pub struct MshvMemoryRegion {
    slot: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    readonly: bool,
    log_dirty_pages: bool,
}

fn convert_c_to_arc<T1: ?Sized, T2>(inptr: Option<NonNull<T1>>) -> Arc<T2> {
    match inptr {
        Some(ptr) => unsafe { Arc::from_raw(ptr.as_ptr() as *const T2) },
        _ => {
            panic!("VM ptr is null");
        }
    }
}

fn convert_arc_to_c<T1: ?Sized, T2>(inptr: Arc<T1>) -> Option<NonNull<T2>> {
    NonNull::new(Arc::into_raw(inptr) as *const T2 as *mut T2)
}

#[no_mangle]
pub extern "C" fn mshv_new() -> Option<NonNull<MshvHypervisorC>> {
    let result = mshv::MshvHypervisor::new();
    result.ok().map(|r| convert_arc_to_c(r).unwrap())
}

#[no_mangle]
//vm_type: 0 -> Normal, 1 -> SNP
pub extern "C" fn mshv_create_vm_with_type(
    rawmshv: Option<NonNull<MshvHypervisorC>>,
    vm_type: u64,
) -> Option<NonNull<MshvVmC>> {
    let mshv: Arc<dyn Hypervisor> =
        convert_c_to_arc::<MshvHypervisorC, mshv::MshvHypervisor>(rawmshv);
    let vm: Arc<dyn Vm> = match mshv.create_vm_with_type(vm_type) {
        Ok(vm) => vm as Arc<dyn Vm>,
        Err(e) => {
            panic!("[mshv] Failed to create a VM: {:?}", e);
        }
    };
    convert_arc_to_c(vm)
}

#[no_mangle]
pub extern "C" fn mshv_new_vcpu(vm: *mut MshvVmC, vcpu: u8) -> Option<NonNull<MshvVcpuC>> {
    unsafe {
        let vcpu = Arc::from_raw(vm as *mut mshv::MshvVm)
            .as_ref()
            .create_vcpu(vcpu, None);
        vcpu.ok().map(|cpu| {
            NonNull::new(Arc::into_raw(cpu) as *mut MshvVcpuC).expect("create_vcpu failed")
        })
    }
}

// register memory in mshv device
#[no_mangle]
pub extern "C" fn mshv_add_mem(rawvm: Option<NonNull<MshvVmC>>, r: &MshvMemoryRegion) -> bool {
    let vm: Arc<dyn Vm> = convert_c_to_arc::<_, mshv::MshvVm>(rawvm);
    let ret = match vm.create_user_memory_region(vm.make_user_memory_region(
        r.slot,
        r.guest_phys_addr,
        r.memory_size,
        r.userspace_addr,
        r.readonly,
        r.log_dirty_pages,
    )) {
        Ok(_) => true,
        _ => false,
    };
    let _ = Arc::into_raw(vm);
    ret
}

// config CPU in mshvcpu device
#[no_mangle]
pub extern "C" fn mshv_configure_vcpu(
    rawcpu: Option<NonNull<MshvVcpuC>>,
    regs: &StandardRegistersC,
    sregs: &SpecialRegistersC,
    fpu: &FpuStateC,
) {
    let vcpu: Arc<dyn Vcpu> = convert_c_to_arc::<_, mshv::MshvVcpu>(rawcpu);

    // Let mshv to fill msr;
    vcpu.set_msrs(&vcpu.boot_msr_entries())
        .expect("failed to set msr");
    let regs: StandardRegisters = (*regs).into();
    let sregs: SpecialRegisters = (*sregs).into();
    let fpu: FpuState = (fpu.clone()).into();
    vcpu.set_regs(&regs).expect("failed to set regs");
    vcpu.set_fpu(&fpu).expect("failed to set fpu");
    vcpu.set_sregs(&sregs).expect("failed to set sregs");
    arch::x86_64::interrupts::set_lint(&vcpu).expect("failed to set interrupt");
    let _ = Arc::into_raw(vcpu);
}

#[repr(C)]
#[derive(Debug)]
pub enum MshvVmExit {
    #[cfg(target_arch = "x86_64")]
    IoapicEoi,
    Ignore,
    Reset,
    Shutdown,
}

#[no_mangle]
pub extern "C" fn mshv_run_vcpu(vcpu: *mut MshvVcpuC, ioacpic_vector: &mut u8) -> MshvVmExit {
    let ret = unsafe {
        (vcpu as *mut mshv::MshvVcpu)
            .as_mut()
            .expect("MshvVcpuC is NULL")
            .run()
    };
    match ret {
        Ok(vmexit) => {
            println!("{:?}", vmexit);
            match vmexit {
                hypervisor::VmExit::IoapicEoi(v) => {
                    *ioacpic_vector = v;
                    MshvVmExit::IoapicEoi
                }
                hypervisor::VmExit::Reset => MshvVmExit::Reset,
                hypervisor::VmExit::Shutdown => MshvVmExit::Shutdown,
                hypervisor::VmExit::Hyperv => {
                    unimplemented! {}
                }
                _ => MshvVmExit::Ignore,
            }
        }
        Err(hverr) => {
            panic!("{}", hverr)
        }
    }
}
