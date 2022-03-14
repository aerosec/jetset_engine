from device.base_device import Simmio
import angr
import cle
from angr.engines.vex.ccall import x86g_use_seg_selector, get_segdescr_limit
import claripy  
from angr.state_plugins.callstack import CallStack   

target = 0x1033734
avoid = [0x1030734 + 0x1ab0] 
arch = "x86"
arch_num = 3

mmio = Simmio( lower=0x21d00000,
               upper=0x21d00000 + 0x1400a3,
                              name='mmio')
regions = [mmio]

def switch_task(state):
    print("=== Doing Task Switch! ===")
    task_offset = state.stack_pop() #translated_pop(state) 
    task_selector = state.stack_pop() #translated_pop(state) 
    task_addr = x86g_use_seg_selector(state,state.regs.ldt,state.regs.gdt,task_selector,task_offset)[0][31:0]

    task_eip = state.memory.load(task_addr + 0x20,4,endness='Iend_LE')
    task_eflags = state.memory.load(task_addr + 0x24,4,endness='Iend_LE')

    task_eax = state.memory.load(task_addr + 0x28,4,endness='Iend_LE')
    task_ecx = state.memory.load(task_addr + 0x2c,4,endness='Iend_LE')
    task_edx = state.memory.load(task_addr + 0x30,4,endness='Iend_LE')
    task_ebx = state.memory.load(task_addr + 0x34,4,endness='Iend_LE')
    task_esp = state.memory.load(task_addr + 0x38,4,endness='Iend_LE')
    task_ebp = state.memory.load(task_addr + 0x3c,4,endness='Iend_LE')
    task_esi = state.memory.load(task_addr + 0x40,4,endness='Iend_LE')
    task_edi = state.memory.load(task_addr + 0x44,4,endness='Iend_LE')

    task_es = state.memory.load(task_addr + 0x48,2,endness='Iend_LE')
    task_cs = state.memory.load(task_addr + 0x4c,2,endness='Iend_LE')
    task_ss = state.memory.load(task_addr + 0x50,2,endness='Iend_LE')
    task_ds = state.memory.load(task_addr + 0x54,2,endness='Iend_LE')
    task_fs = state.memory.load(task_addr + 0x58,2,endness='Iend_LE')
    task_gs = state.memory.load(task_addr + 0x5c,2,endness='Iend_LE')
    translated_task_eip = x86g_use_seg_selector(state,state.regs.ldt,state.regs.gdt,task_cs.zero_extend(16), task_eip)[0][31:0]

    new_frame = CallStack(func_addr=state.solver.eval(translated_task_eip), 
        call_site_addr = state.solver.eval(state.regs.eip), 
        jumpkind='Ijk_Call', 
        stack_ptr = state.solver.eval(task_esp), 
        ret_addr = state.solver.eval(state.regs.eip))
    state.callstack.push(new_frame)

    state.regs.eip = translated_task_eip
    state.regs.eflags = task_eflags 

    state.regs.eax = task_eax
    state.regs.ecx = task_ecx 
    state.regs.edx = task_edx  
    state.regs.ebx = task_ebx 
    state.regs.esp = task_esp 
    state.regs.ebp = task_ebp 
    state.regs.esi = task_esi 
    state.regs.esi = task_edi

    state.regs.es = task_es 
    state.regs.cs = task_cs 
    state.regs.ss = task_ss  
    state.regs.ds = task_ds  
    state.regs.fs = task_fs  
    state.regs.gs = task_gs

def get_project():        
    boot_path = "../firmware/cmu/boot.bin"
    data_path = "../firmware/cmu/data.bin"
    app_path = "../firmware/cmu/app.bin"

    boot_load_opts = {'backend' : 'blob',
                      'base_addr' : 0xfff00000,
                      'entry_point' : 0xfffe20fc,
                      'arch' : 'x86'}
    p=angr.Project(boot_path,load_options={'main_opts':boot_load_opts,'rebase_granularity':0x1000,'page_size':1},auto_load_libs=False)

    #Load data blob
    data_backend = cle.backends.Blob(data_path,arch='x86',base_addr=0x41000000)
    p.loader.add_object(data_backend)

    #Load app blob
    app8 = (0x100,0x1000100,0x458)
    app10 = (0x558,0x1000558,0x298)#might be 2a0 add a +10?
    app28 = (0x30732,0x1030732,0x7000)#might be 3ebe
    app30 = (0x2dd4,0x600,0x9ce0) # Not sure about this one
    app18 = (0x7f0,0x10007f0, 0x118)  # isn't app 18 mapped to 0x4154 , or is ldt copied at some point
    app70 = (0x970, 0x1000970, 0x2fdc2)
    app168 = (0x440000, 0x1440000, 0x80000)
    appf0 = (0x12d9, 0x00000000, 0x20d0)
    app1e8 = (0x005c0000, 0x15c0000, 0x40000)
    app48 = (0x918, 0x1000918, 0x68)
    app160 = (0x003c0000,0x013c0000, 0x80000)
    app120 = (0x00800000, 0x01800000, 0x120)
    app118 = (0x00000908 , 0x01000908, 0x67)
    app170 = (0x00380000, 0x01380000, 0x3ffff)
    appb0 = (0x00f80000, 0x01f80000, 0x3ffff) # ioproc
    appb8 = (0x00f40000, 0x01f40000, 0x1ffff) # anaproc
    app_segments = [app8,app10,app28,app30,app18,app70,app168, appf0, app1e8,app48, app160, app120, app170, app118, appb0, appb8]
    app_backend = cle.backends.Blob(app_path,arch='x86',segments=app_segments)
    p.loader.add_object(app_backend)

    p.hook(0xfffe288b,switch_task)

    return p

