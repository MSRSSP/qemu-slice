use hypervisor::{mshv, Hypervisor, Vcpu, Vm};
pub use mshv_ioctls::VmType;
use std::{ptr::NonNull, sync::Arc};

#[repr(C)]
pub struct MshvVmC;

#[repr(C)]
pub struct MshvHypervisorC;

#[repr(C)]
pub struct MshvVcpuC;

#[no_mangle]
pub extern "C" fn mshv_new() -> Option<NonNull<MshvHypervisorC>> {
    let result = mshv::MshvHypervisor::new();
    match result {
        Ok(mshv) => {
            let tmp = NonNull::new(Arc::into_raw(mshv) as *const () as *mut MshvHypervisorC);
            let tmp = tmp.expect("Result contained None, which is unexpected");
            Some(tmp)
        }
        _ => None,
    }
}

#[no_mangle]
//vm_type: 0 -> Normal, 1 -> SNP
pub extern "C" fn mshv_create_vm_with_type(
    mshv: *mut MshvHypervisorC,
    vm_type: u64,
) -> Option<NonNull<MshvVmC>> {
    unsafe {
        let mshv = (mshv as *mut mshv::MshvHypervisor)
            .as_mut()
            .expect("MshvHypervisor is NULL");
        let result = mshv.create_vm_with_type(vm_type);
        match result {
            Ok(vm) => {
                Some(NonNull::new(Arc::into_raw(vm) as *const () as *mut MshvVmC)
                .expect("Result contained None, which is unexpected"))
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn mshv_new_vcpu(vm: *mut MshvVmC, vcpu: u8) -> Option<NonNull<MshvVcpuC>> {
    unsafe {
        let vcpu = (vm as *mut mshv::MshvVm)
            .as_ref()
            .expect("MshvVm is NULL")
            .create_vcpu(vcpu, None);
        vcpu.ok()
            .map(|cpu| NonNull::new(Arc::into_raw(cpu) as *mut MshvVcpuC).expect("create_vcpu failed"))
    }
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
    let ret = unsafe { (vcpu as *mut mshv::MshvVcpu).as_mut().expect("MshvVcpuC is NULL").run() };
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
