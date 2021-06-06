import claripy

BSWAP_MASK = 0x0000ff00

def bswap32(arg):
    t0 = arg << 24

    t1 = (arg & BSWAP32_MASK) << 8
    t0 = t0 | t1

    t1 = (arg >> 8) & BSWAP32_MASK
    t0 = t0 | t1

    t1 = arg >> 24
    return t0 | t1

def rotl(arg1, arg2):
    t0 = arg1 << arg2
    t1 = 32 - arg2
    t1 = arg1 >> t1
    return t0 | t1

def rotr(arg1, arg2):
    t0 = arg1 >> arg2
    t1 = 32 - arg2
    t1 = arg1 << t1
    return t0 | t1

# See TCG_COND_* consts defined in tcg.h in QEMU
cond_to_constraint = {
    # non-signed
    0: lambda x, y: False,
    1: lambda x, y: True,
    8: lambda x, y: x == y,
    9: lambda x, y: x != y,
    # signed
    2: lambda x, y:  claripy.SLT(x, y),
    3: lambda x, y:  claripy.SGE(x, y),
    10: lambda x, y: claripy.SLE(x, y),
    11: lambda x, y: claripy.SGT(x, y),
    # unsigned
    4: lambda x, y:  claripy.ULT(x, y),
    5: lambda x, y:  claripy.UGE(x, y),
    12: lambda x, y: claripy.ULE(x, y),
    13: lambda x, y: claripy.UGT(x, y)
}

# TODO: wrap binary ops with a zero-extend
op_to_constraint = {
    0: lambda x: x,
    1: lambda x, y: x + y,
    2: lambda x, y: x - y,
    3: lambda x, y: x * y,
    4: lambda x, y: claripy.Sdiv(x, y),
    5: lambda x, y: x / y,
    6: lambda x, y: claripy.Smod(x, y),
    7: lambda x, y: x % y,
    8: lambda x, y: x & y,
    9: lambda x, y: x | y,
    10: lambda x, y: x ^ y,
    11: lambda x, y: x << y,
    12: lambda x, y: x >> y,
    13: lambda x, y: claripy.LShR(x, y),
    14: rotl,
    15: rotr,
    # zero-extend by one to avoid edge-case where size = extract.
    16: lambda x: x.zero_extend(max(1, 9 - x.size()))[7:].sign_extend(24),
    17: lambda x: x.zero_extend(max(1, 17 - x.size()))[15:].sign_extend(16),
    18: lambda x: x.zero_extend(max(1, 9 - x.size()))[7:].zero_extend(24),
    19: lambda x: x.zero_extend(max(1, 17 - x.size()))[15:].zero_extend(16),
    20: bswap32,
    21: bswap32,
    22: lambda x: ~x,
    23: lambda x: -x,
    24: lambda x: x,
    25: lambda x, y: x + y,
    26: lambda x, y: x - y,
    27: lambda x, y: x * y,
    28: lambda x, y: x & y,
    29: lambda x, y: x | y,
    30: lambda x, y: x ^ y,
    31: lambda x, y: x << y,
    32: lambda x, y: x >> y,
    33: lambda x, y: claripy.LShR(x, y),
    34: rotl,
    35: rotr,
    36: lambda x: x.zero_extend(max(1, 9 - x.size()))[7:].zero_extend(24),
    37: lambda x: x.zero_extend(max(1, 9 - x.size()))[7:].sign_extend(24),
    38: lambda x: x.zero_extend(max(1, 17 - x.size()))[15:].sign_extend(16),
    39: lambda x: x.zero_extend(max(1, 17 - x.size()))[15:].zero_extend(16),
    # QEMU TCG Only Emits / Deals with 32/64 bit register values;
    # since we can have BVs less than 32 bits, we do sanity checking
    # here. Alternatively we could augment QEMU; since we emit QMP
    # commands long after the operand metadata is lost, this sanity
    # checking suffices.
    # INDEX_op_ext_i32_i64
    40: lambda x: x[x.size() - 1:].sign_extend(64 - x.size()),
    # INDEX_op_extu_i32_i64
    41: lambda x: x[x.size() - 1:].zero_extend(64 - x.size()),
    42: bswap32,
    43: bswap32,
    44: bswap32,
    45: lambda x: ~x,
    46: lambda x: -x
}

x86_flags = {
    0x1 :  lambda x: claripy.If(((x & 0xffffffff) == 0), claripy.BVV(0x40,32), claripy.BVV(0,32)), #eflags
    0xe:   lambda x: claripy.If(((x & 0x000000ff) == 0), claripy.BVV(0x40,32), claripy.BVV(0,32)),  # modify all flags, CC_DST = res, CC_SRC = src1 
    0x16 : lambda x: claripy.If(((x & 0x000000ff) == 0), claripy.BVV(0x40,32), claripy.BVV(0,32)),  # modify all flags, CC_DST = res
    0x17 : lambda x: claripy.If(((x & 0x0000ffff) == 0), claripy.BVV(0x40,32), claripy.BVV(0,32)),
    0x18:  lambda x: claripy.If(((x & 0xffffffff) == 0), claripy.BVV(0x40,32), claripy.BVV(0,32)),
    0x26: lambda x: claripy.If(((x & 0x000000ff) == 0), claripy.BVV(0x40,32), claripy.BVV(0,32)),
    0x27: lambda x: claripy.If(((x & 0x0000ffff) == 0), claripy.BVV(0x40,32), claripy.BVV(0,32)),
    0x28: lambda x: claripy.If(((x & 0xffffffff) == 0), claripy.BVV(0x40,32), claripy.BVV(0,32)),
    0x31 : lambda x: claripy.BVV(0,32)
}

def coerce_args(v0, v1):
    """
    Handles QEMU's weird emission of 64 bit values with 32 bit unsigned
    partner operands
    """
    if type(v0) != int and type(v1) != int and (len(v0) != len(v1)):
        if (len(v0) > len(v1)):
            v1 = v1.zero_extend(len(v0) - len(v1))
        else:
            v0 = v0.zero_extend(len(v1) - len(v0))
    return v0, v1

def binop_to_constraint(opc, v0, v1):
    v0, v1 = coerce_args(v0, v1)
    return op_to_constraint[opc](v0, v1)

def unop_to_constraint(opc, v):
    return op_to_constraint[opc](v)

def deposit_to_constraint(v0, v1, c0, c1):
    v0, v1 = coerce_args(v0, v1)
    return (v0 & ~c1) | ((v1 << c0) & c1)

def setcond_to_constraint(condition, v0, v1):
    v0, v1 = coerce_args(v0, v1)
    bool_constraint = cond_to_constraint[condition](v0, v1)
    constraint = claripy.If(bool_constraint, claripy.BVV(1, 32),
                            claripy.BVV(0, 32))
    return constraint


def choice_to_constraint(condition, v0, v1):
    v0, v1 = coerce_args(v0, v1)
    return cond_to_constraint[condition](v0,v1)
