#include "qemu/osdep.h"
#include "qemu/module.h"


#include "qapi/error.h"
#include "qemu/accel.h"
#include "qemu/error-report.h"
#include "sysemu/cpus.h"

#include "hw/boards.h"
#include "sysemu/stats.h"

#include "mshv-ioctls.h"

typedef struct MSHVState {
  AccelState parent_obj;
  struct Mshv mshv;
  struct VmFd vmfd;
} MSHVState;

#define TYPE_MSHV_ACCEL ACCEL_CLASS_NAME("mshv")

DECLARE_INSTANCE_CHECKER(MSHVState, MSHV_STATE, TYPE_MSHV_ACCEL)

bool mshv_allowed;

static int mshv_init(MachineState *ms) {
  MachineClass *mc = MACHINE_GET_CLASS(ms);
  MSHVState *s;
  VmFd ret;
  VmType type;

  s = MSHV_STATE(ms->accelerator);

  s->mshv = mshv_new();

  // TODO: object_property_find(OBJECT(current_machine), "mshv-type")
  type = Normal;
  do {
    ret = mshv_create_vm_with_type(s->mshv, type);
  } while (ret.vmfd == NULL);

  s->vmfd = ret;
  mc->default_ram_id = NULL;

  return 0;
}

static void mshv_accel_class_init(ObjectClass *oc, void *data) {
  AccelClass *ac = ACCEL_CLASS(oc);

  ac->name = "MSHV";
  ac->init_machine = mshv_init;
  ac->allowed = &mshv_allowed;
}

static void mshv_accel_instance_init(Object *obj)
{
    MSHVState *s = MSHV_STATE(obj);

    s->mshv.mshv = NULL;
    s->vmfd.vmfd = NULL;
}

static const TypeInfo mshv_accel_type = {
    .name = TYPE_MSHV_ACCEL,
    .parent = TYPE_ACCEL,
    .instance_init = mshv_accel_instance_init,
    .class_init = mshv_accel_class_init,
    .instance_size = sizeof(MSHVState),
};

static void mshv_accel_ops_class_init(ObjectClass *oc, void *data)
{
    AccelOpsClass *ops = ACCEL_OPS_CLASS(oc);

    ops->create_vcpu_thread = dummy_start_vcpu_thread;
}

static const TypeInfo mshv_accel_ops_type = {
    .name = ACCEL_OPS_NAME("mshv"),
    .parent = TYPE_ACCEL_OPS,
    .class_init = mshv_accel_ops_class_init,
    .abstract = true,
};

static void mshv_type_init(void) {
  type_register_static(&mshv_accel_type);
  type_register_static(&mshv_accel_ops_type);
}

type_init(mshv_type_init);