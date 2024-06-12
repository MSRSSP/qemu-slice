
#ifndef QEMU_MSHV_INT_H
#define QEMU_MSHV_INT_H

#include "exec/memory.h"
#include "qapi/qapi-types-common.h"
#include "qemu/accel.h"
#include "qemu/queue.h"
#include "qemu/accel.h"
#include "qemu/log.h"

#include <mshv.h>

#define LOG_MSHV_MASK LOG_GUEST_ERROR

#define mshv_log(FMT, ...)                                                     \
    do {                                                                       \
        qemu_log_mask(LOG_MSHV_MASK, FMT, ##__VA_ARGS__);                      \
    } while (0)

#define mshv_debug()                                                           \
    do {                                                                       \
        mshv_log("%s:%d\n", __func__, __LINE__);                               \
    } while (0)

#define mshv_todo()                                                            \
    do {                                                                       \
        mshv_log("[todo]%s:%d\n", __func__, __LINE__);                         \
    } while (0)

typedef struct MshvMemoryUpdate {
    QSIMPLEQ_ENTRY(MshvMemoryUpdate) next;
    MemoryRegionSection section;
} MshvMemoryUpdate;

typedef struct MshvMemoryListener {
    MemoryListener listener;
    MshvMemoryRegion *slots;
    unsigned int nr_used_slots;
    int as_id;
    QSIMPLEQ_HEAD(, MshvMemoryUpdate) transaction_add;
    QSIMPLEQ_HEAD(, MshvMemoryUpdate) transaction_del;
} MshvMemoryListener;

typedef struct MshvState {
    AccelState parent_obj;
    MshvHypervisorC *mshv;
    MshvVmC *vm;
    int nr_slot; // max number of memory region per listener;
    MshvMemoryListener memory_listener;
    int nr_as; // number of listener;
    struct MshvAs {
        MshvMemoryListener *ml;
        AddressSpace *as;
    } * as;
} MshvState;

bool mshv_arch_init(MachineState *ms, MshvState *s);

void mshv_memory_listener_register(MshvState *s, MshvMemoryListener *mml,
                                          AddressSpace *as, int as_id,
                                          const char *name);
#endif