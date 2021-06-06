from collections import defaultdict
import device.device_templates as qt
import collections
import claripy


def get_base(io_clusters, portno):
    for base,ports in io_clusters.items():
        if portno in ports:
            return base

def get_trace(device, region):
    trace = []
    for mmio_read in device.mmio_reads():
        if (mmio_read.addr >= region.lower) and (mmio_read.addr <= region.upper):
            trace.append((mmio_read.addr, mmio_read.symbol))

    return trace


# Top level should be state -> string
def get_trace_dict(device, region):
    # Trace = tuples of (addr, value read)
    trace = get_trace(device, region)
    num_reads = len(trace)

    # Create a dict of traces based upon the address used to read
    trace_dict = collections.defaultdict(list)
    for a, v in trace:
        trace_dict[a].append(v)

    return trace_dict, num_reads


def decrementer(device, vlist):
    if not vlist:
        return 0

    vlist = iter(reversed(vlist))
    last = next(vlist)
    r = 0

    for i, item in enumerate(vlist):
        if device.link.vars_linked(list(last.variables)[0], list(item.variables)[0]):
            r = i

    return r


def mk_statestruct(device, n, ioport_traces):
    statestruct = qt.statestruct_prefix
    for base in ioport_traces:
        statestruct += qt.statestruct_entry_template.format(hex(base), hex(base))
    for base,portmap in ioport_traces.items():
        for port, vals in portmap.items():
            statestruct += qt.read_array_template.format(
                hex(base), hex(port), len([len(vals), 0] + vals))

    for region in device.regions:
        statestruct += qt.statestruct_entry_template.format(region.name)
        trace_dict, num_reads = get_trace_dict(device, region)
        for a, vs in trace_dict.items():
            statestruct += qt.read_array_template.format(
                region.name, hex(a), len([len(vs), 0] + vs))

        for gpio_in in region.gpio_in:
            if gpio_in.width > 1:
                statestruct += qt.rpi_intr_irq_decl_multi.format(region.name + "_irq_" + str(gpio_in.index) , gpio_in.width)
            else:
                statestruct += qt.rpi_intr_irq_decl.format(region.name + "_irq_" + str(gpio_in.index) )

        for gpio_out in region.gpio_out:
            if gpio_out.width > 1:
                statestruct += qt.rpi_intr_irq_decl_multi.format(region.name + "_irq_" + str(gpio_out.index) , gpio_out.width)
            else:
                statestruct += qt.rpi_intr_irq_decl.format(region.name + "_irq_" + str(gpio_out.index) )


    intr_statestruct = qt.rpi_intr_statestruct
    for subdev in device.regions:
        for gpio_in in subdev.gpio_in:
            intr_statestruct += qt.rpi_trigger.format(subdev.name + "_trigger_" + str(gpio_in.index))

    statestruct += intr_statestruct
    statestruct += qt.statestruct_suffix
    return statestruct

# [ event ] -> { addr -> [value]}
# def split_trace()

def get_ioport_trace(device, ports):
    trace = []
    for io_read in device.ioport_reads():
        if io_read.portno in ports:
            v = device.eval(io_read.symbol)
            trace.append(v)
    return trace


# make handlers for all devices
def mk_handlers(device, ioport_traces):
    handlers = ""
    decls = ""
    idx = 0

    # Make port mapped io handlers
    '''
    for start, ports in io_clusters.items():
        trace = get_ioport_trace(device, ports)        
        num_reads = len(trace)
        handlers += qt.write_handler_template.format(idx)
        trace_str = str([hex(v) for v in trace])[1:-1].replace("'", "")
        handlers += qt.ioport_read_handler_template.format(
            idx, idx, num_reads, idx, num_reads, trace_str, idx, idx, idx,
            hex(trace[-1]) if trace else hex(0xffffffff))
        handlers += qt.op_decl_template.format(idx, idx, idx)
        num_ioports = max(ports) - start + 1
        decls += qt.ioport_decl_template.format(idx, idx, num_ioports,
                                                    hex(start), num_ioports,
                                                    hex(start), idx)
        idx += 1
    '''


    for base,portmap in ioport_traces.items():
        name = hex(base)
        handlers += qt.write_handler_template.format(name, hex(base))

        #trace_dict, num_reads = get_trace_dict(device, region)

        # create a switch cases and arrays for each addr of
        # [len of trace, idx, trace..]
        case_str = '\n'.join(
            [qt.read_case_template.format(name, hex(a), hex(base), 0) for a in portmap.keys()])

        num_reads = sum([len(trace) for trace in portmap.values()])

        # See qt.read_handler_template
        if num_reads:
            handlers += qt.read_handler_template.format(
                hex(base), num_reads, case_str, hex(base))
        else:
            handlers += qt.read_handler_template_empty.format(hex(base), num_reads)

        handlers += qt.op_decl_template.format(hex(base), hex(base))
        num_ioports = max(portmap.keys()) - base + 1
        decls += qt.ioport_decl_template.format(hex(base), hex(base), num_ioports,
                                                    hex(base), num_ioports,
                                                    hex(base), hex(base))


    # make mmio handlers
    for region in device.regions:
        name = region.name
        handlers += qt.write_handler_template.format(name, hex(region.lower))
        if region.is_ic:

            if region.name == "ic":
                handlers += qt.ic_read_handler_template1.format(region.name + "_pending_intr")
            elif region.name == "soc_control":
                handlers += qt.ic_read_handler_template0.format(region.name + "_pending_intr")
            else:
                raise Exception("Invalid interrupt controller")

            start = region.lower
            size = region.upper - region.lower + 1
            decls += qt.mmio_decl_template.format(name, name, hex(size), name,
                                              hex(start), name)

            handlers += qt.op_decl_template.format(name, hex(region.lower))
            continue



        trace_dict, num_reads = get_trace_dict(device, region)

        # create a switch cases and arrays for each addr of
        # [len of trace, idx, trace..]
        case_str = '\n'.join(
            [qt.read_case_template.format(name, hex(a), hex(region.lower), decrementer(device, v)) for a, v in trace_dict.items()])

        # See qt.read_handler_template
        if num_reads:
            handlers += qt.read_handler_template.format(
                name, num_reads, case_str, hex(region.lower))
        else:
            handlers += qt.read_handler_template_empty.format(name, num_reads)

        handlers += qt.op_decl_template.format(name, hex(region.lower))
        start = region.lower
        size = region.upper - region.lower + 1
        decls += qt.mmio_decl_template.format(name, name, hex(size), name,
                                              hex(start), name)

    return handlers, decls


def mk_reset(device, n, ioport_traces):
    reset = qt.reset_prefix
    for base, portmap in ioport_traces.items():
        for port, vals in portmap.items():
            c_trace_array = str([len(vals), 0] + [hex(v) for v in vals]).replace("'", "")
            c_trace_array = c_trace_array.replace("[", "{").replace("]", "}")
            reset += qt.reset_entry_template.format(hex(base), hex(port),
                                                    c_trace_array,
                                                    len(vals) + 2)

    for region in device.regions:
        trace_dict, num_reads = get_trace_dict(device, region)
        for addr, vs in trace_dict.items():
            c_trace_array = str(
                [len(vs), 0] +
                list(map(hex, [device.solver.eval(v, 1)[0]
                               for v in vs]))).replace("'", "")
            c_trace_array = c_trace_array.replace("[", "{").replace("]", "}")
            reset += qt.reset_entry_template.format(region.name, hex(addr),
                                                    c_trace_array,
                                                    len(vs) + 2)
    reset += "}"
    return reset


# ========== Preprocessing ==============


def cluster_ports(device):
    '''
    Cluster port-mapped I/O traces by location
    '''
    idx = -1
    io_clusters = defaultdict(list)
    # sorted list of addr reads
    portlist = [event.portno for event in device.trace if event.is_ioport]
    ports = sorted(list(set(portlist)))
    for addr in ports:
        if idx == -1:
            io_clusters[addr].append(addr)
            idx = addr
        else:
            if addr - idx > 8:
                io_clusters[addr].append(addr)
                idx = addr
            else:
                io_clusters[idx].append(addr)

    return dict(io_clusters)

def get_single_port_trace(device, port):
    trace = []
    for io_read in device.ioport_reads():
        if io_read.portno == port:
            v = device.eval(io_read.symbol)
            trace.append(v)
    return trace

def get_complete_ioport_traces(device):
    ioport_traces = defaultdict(dict)
    clustered_ports = cluster_ports(device)
    for base,ports in clustered_ports.items():
        for port in ports:
            ioport_traces[base][port] = get_single_port_trace(device, port)
    return dict(ioport_traces)

#device = symbolic_device
def mk_device(device, rpi=False):
    assert(device.solver.satisfiable())
    io_clusters = cluster_ports(device)
    ioport_traces = get_complete_ioport_traces(device)
    n = len(io_clusters)
    handlers, decls = mk_handlers(device, ioport_traces)

    statestruct = mk_statestruct(device, n, ioport_traces)
    reset = mk_reset(device, n, ioport_traces)
    if rpi:
        intr_func = qt.rpi_intr_func0
        intr_func += qt.rpi_next_intr.format("ic_pending_intr", 16) + qt.rpi_next_intr.format("soc_control_pending_intr",16)
        intr_func += qt.rpi_intr_func3.format("soc_control_pending_intr")
        for subdev in device.regions:
            if subdev.is_ic:
                for gpio_in in subdev.gpio_in:
                    intr_func += qt.rpi_intr_outer.format(subdev.name + "_irq_" + str(gpio_in.index), subdev.name + "_trigger_" + str(gpio_in.index), subdev.name + "_update")
    else:
        intr_func = ""

    if rpi:
        for subdev in device.regions:
            if subdev.is_ic:
                for gpio_in in subdev.gpio_in:
                    decls += qt.rpi_gpio_in_init.format(subdev.name + "_irq_" + str(gpio_in.index), '"' + gpio_in.name + '"', gpio_in.width)
                for gpio_out in subdev.gpio_out:
                    if gpio_out.is_irq:
                        decls += qt.rpi_init_irq_out.format(subdev.name + "_irq_" + str(gpio_out.index))
                    else:
                        decls += qt.rpi_gpio_out_init.format(subdev.name + "_irq_" + str(gpio_out.index) , '"' + gpio_out.name + '"', gpio_out.width)


    device_str = qt.device_template.format(statestruct, intr_func, handlers, decls,
                                       reset)
    print(device_str)
    return device_str




def cluster_mmio(device):
    mmio = defaultdict(set)
    for region in device.regions:
        for event in device.trace:
            if event.is_mmio:
                name = get_region_name(device, event.addr)
                mmio[name].add(event.addr)
    return mmio


def get_region_name(device, addr):
    for region in device.regions:
        if (addr >= region.lower) and (addr < region.upper):
            return region.name


def io_protocol_summary(device):
    io_clusters = cluster_ports(device)

    format_array = defaultdict(dict)
    for base,ports in io_clusters.items():
        for port in ports:
            format_array[base][port] = ""

    for event in device.trace:
        if event.is_ioport:
            base = get_base(io_clusters, event.portno)
            if event.is_read:
                s = f"{hex(event.portno)} <- {hex(device.solver.eval(event.symbol,1)[0] )}  "
            else:
                s = f"{hex(event.val)} -> {hex(event.portno)}  "

            for port in format_array[base]:
                if port == event.portno:
                    format_array[base][port] += s
                else:
                    format_array[base][port] += " " * len(s)

    clustered_mmio = cluster_mmio(device)
    mmio_format_array = defaultdict(dict)

    for name,addrs in clustered_mmio.items():
        for addr in addrs:
            mmio_format_array[name][addr] = ""



    for event in device.trace:
        if event.is_mmio:
            name = get_region_name(device, event.addr)
            if event.is_read:
                s = f"{hex(event.addr)} <- {hex(device.solver.eval(event.symbol,1)[0] )}  "
            else:
                s = f"{hex(event.val)} -> {hex(event.addr)}  "

            for addr in mmio_format_array[name]:
                if addr == event.addr:
                    mmio_format_array[name][addr] += s
                else:
                    mmio_format_array[name][addr] += " " * len(s)


    s = "===== Ioport =====\n"
    for subdev,strings in format_array.items():
        for port, string in strings.items():
            s += (hex(port) + ": " + string + "\n")
        s += "\n"
    s += "\n\n ===== MMIO ===== \n\n"
    for subdev,strings in mmio_format_array.items():
        for addr,string in strings.items():
            s += (hex(addr) + " : " + string + "\n")
        s += "\n"

    return s
