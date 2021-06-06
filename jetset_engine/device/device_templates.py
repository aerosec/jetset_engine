intr_func_prefix = '''
static void maybe_intr(void *opaque){
'''

intr_func_handler = '''
if (global_idx == {})
        set_irq(opaque, {}, 1);
'''

intr_func_suffix = '''
    return;
}
'''

# ========= statestruct =============

statestruct_prefix = '''
typedef struct {
    SysBusDevice parent_obj;
    qemu_irq* irq_set;
    int global_idx;

'''

statestruct_entry_template = '''
    MemoryRegion io_{0};
'''

statestruct_idx_template = '''
     unsigned int index{};
'''

read_array_template = '''
    uint64_t io_read_trace_{0}_{1}[{2}];
'''

statestruct_suffix = "} SynthState;"

# Handler Creation ================

write_handler_template = '''
static void synth_write_{0}(
    void *opaque, hwaddr addr, uint64_t val, unsigned size)
{{
#ifdef PAPER_EVAL
        fprintf(stderr, "WRITE {0} ADDR 0x%lx\\n", addr);
#endif
        printf("\%c" ,(char)val);
        fflush(stdout);
}}
'''

ioport_read_handler_template = '''
int io_read_idx_{} = 0;
int num_recorded_reads_{} = {};
static uint64_t synth_read_{}(void *opaque, hwaddr addr, unsigned size) {{
    int read_queue[{}] = {{ {} }};
    if (io_read_idx_{} < num_recorded_reads_{}){{
        return read_queue[io_read_idx_{}++];
        }}
    else
        return {};
}}
'''

read_case_template = '''
        case {1} - {2}:
            if (sio->io_read_trace_{0}_{1}[1] < sio->io_read_trace_{0}_{1}[0]) {{
                sio->io_read_trace_{0}_{1}[1]++;
            }} else {{
                sio->io_read_trace_{0}_{1}[1] -= {3};
            }}
            res = sio->io_read_trace_{0}_{1}[sio->io_read_trace_{0}_{1}[1] + 1];
            break;
'''

read_handler_template = '''
static uint64_t synth_read_{0}(void *opaque, hwaddr addr, unsigned size) {{
    SynthState * sio = opaque;
    uint64_t res;
    switch(addr) {{
        {2}
        default:
            res = 0xffffffffffffffff;
            break;
    }}
#ifdef PAPER_EVAL
    fprintf(stderr, "READ {0} ADDR 0x%lx VAL 0x%lx\\n", addr, res);
#endif
    return res;
}}
'''

read_handler_template_empty = '''
static uint64_t synth_read_{0}(void *opaque, hwaddr addr, unsigned size) {{
#ifdef PAPER_EVAL
    fprintf(stderr, "READ {0} ADDR 0x%lx VAL 0xffffffffffffffff\\n", addr);
#endif
    return 0xffffffffffffffff;
}}
'''

op_decl_template = '''
static const MemoryRegionOps synth_io_ops_{0} =
{{
    .write = synth_write_{0},
    .read = synth_read_{0},
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
    .endianness = DEVICE_NATIVE_ENDIAN,
}};
'''

# MMIO and IO Declarations

mmio_decl_template = '''
    memory_region_init_io(
        &sio->io_{}, obj, &synth_io_ops_{}, sio, TYPE_SYNTH, {}
    );
    sysbus_init_mmio(dev, &sio->io_{});
    memory_region_add_subregion(sysbus, {}, &sio->io_{});
'''

ioport_decl_template = '''
    memory_region_init_io(
        &sio->io_{}, OBJECT(sio), &synth_io_ops_{}, sio, TYPE_SYNTH, {}
    );
    sysbus_init_ioports(dev, {}, {});
    sysbus_add_io(dev, {}, &sio->io_{});
'''

# ========== Reset ===============

reset_prefix = '''
static void synth_reset(DeviceState *d)
{
    SynthState *sio = SYNTH(d);\n
    sio->global_idx = 0;
'''

reset_entry_ioport = '''
    sio->index{} = 0;
'''

reset_entry_template = '''
    uint64_t trace_{0}_{1}[] = {2};
    for (int i = 0; i < {3}; i++) {{
        sio->io_read_trace_{0}_{1}[i] = trace_{0}_{1}[i];
    }}
'''

device_template = '''
#include "qemu/osdep.h"
#include "hw/qdev.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/i386/pc.h"
#include <unistd.h>

#define TYPE_SYNTH "synth"
#define SYNTH(obj) OBJECT_CHECK(SynthState, (obj), TYPE_SYNTH)
//#define ARM_IRQS 8
//#define BCM2835_IC_ARM_IRQ "arm-irq"

{}
{}
{}
static void synth_init(Object *d){{}}

static void synth_realize(DeviceState *d, Error **errp)
{{
    SysBusDevice *dev = SYS_BUS_DEVICE(d);
    SynthState *sio = SYNTH(d);
    Object *obj = OBJECT(sio);
    MemoryRegion *sysbus = sysbus_address_space(dev);
    {}
}}

{}

static void synth_class_init(ObjectClass *klass, void *data)
{{
        DeviceClass *dc = DEVICE_CLASS(klass);
        dc->realize = synth_realize;
        dc->reset = synth_reset;
        set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}}

static const TypeInfo synth_info =
{{
        .name           = TYPE_SYNTH,
        .parent         = TYPE_SYS_BUS_DEVICE,
        .instance_size  = sizeof(SynthState),
        .instance_init  = synth_init,
        .class_init     = synth_class_init,
}};
static void synth_register_types(void)
{{
        type_register_static(&synth_info);
}}

type_init(synth_register_types)
'''

#limit
rpi_next_intr = '''
static uint8_t {0} = 0;
static int next_{0}(void)
{{
  {0}++;
  if({0} > {1}) {{
    {0} = 0;
    return 0;
  }}
  return 1 << {0};
}}
'''

rpi_intr_func3 = '''
/* Update interrupts.  */
static void synth_soc_control_update(SynthState *s)
{{
    s->irq_reg2 = 0;

    if (s->soc_control_trigger_0 && {0} == 0) {{
        {0} = 1;
    }}

    if(s->soc_control_trigger_1 != 0){{
        s->irq_reg2 |= (uint32_t)1 << 3;
    }}

    qemu_set_irq(s->soc_control_irq_2, (s->irq_reg2 != 0) || ({0} != 0));
}}
'''

rpi_intr_func0 = '''

static void ic_irq_0(void *opaque, int irq, int level)
{
    SynthState* s = opaque;
    qemu_set_irq(s->ic_irq_1, level);
}
'''

#gpio_outer func name, trigger variable, gpio_update_func
rpi_intr_outer = '''
static void {}(void *opaque, int irq, int level)
{{
    SynthState *s = opaque;
    s->{} = level;
    synth_{}(s);
}}
'''

# gpio func name, gpio name, width
rpi_gpio_in_init = '''  qdev_init_gpio_in_named(DEVICE(dev), {}, {}, {});
'''

#backing irq name, gpio name, width
rpi_gpio_out_init = ''' qdev_init_gpio_out_named(DEVICE(dev), &sio->{}, {}, {});
'''

#backing irq name
rpi_init_irq_out = ''' sysbus_init_irq(SYS_BUS_DEVICE(dev), &sio->{});
'''

ic_read_handler_template0 = '''
static uint64_t synth_read_soc_control(void *opaque, hwaddr addr, unsigned size)
{{
    SynthState *s = opaque;
    uint32_t v = s->irq_reg2;
    if({0})
        v = next_{0}();
    return v;
}}
'''

ic_read_handler_template1 = '''
static uint64_t synth_read_ic(void *opaque, hwaddr addr, unsigned size) {{
    uint32_t v = next_{0}();
    return v;
}}
'''

rpi_trigger = ''' uint32_t {}; 
''' 

rpi_intr_statestruct = '''
    uint32_t irq_reg2;
'''

#backing irq name
rpi_intr_irq_decl = ''' qemu_irq {};
'''
#backing irq name, width + 1
rpi_intr_irq_decl_multi = ''' qemu_irq {}[{}];
'''
