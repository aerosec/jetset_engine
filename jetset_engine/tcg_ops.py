
#breakpoint types
BP_TARGET_FOUND = 0
BP_AVOID = 1

'''
TCG_COND_NEVER  = 0 | 0 | 0 | 0,
TCG_COND_ALWAYS = 0 | 0 | 0 | 1,
TCG_COND_EQ     = 8 | 0 | 0 | 0,
TCG_COND_NE     = 8 | 0 | 0 | 1,
/* signed */
TCG_COND_LT     = 0 | 0 | 2 | 0,
TCG_COND_GE     = 0 | 0 | 2 | 1,
TCG_COND_LE     = 8 | 0 | 2 | 0,
TCG_COND_GT     = 8 | 0 | 2 | 1,
/* unsigned */
TCG_COND_LTU    = 0 | 4 | 0 | 0,
TCG_COND_GEU    = 0 | 4 | 0 | 1,
TCG_COND_LEU    = 8 | 4 | 0 | 0,
TCG_COND_GTU    = 8 | 4 | 0 | 1,
'''

cond_strs = {0 : "never",
             1 : "always",
             8 : "==",
             9 : "!=",
             2 : '<',
             3 : '>=',
             10 : '<=',
             11 : '>',
             4 : '<',
             5 : '>=',
             12 : '<=',
             13 : '>'}




opc_strs = {0 : "",
             1 : "+",
             2 : "-",
             3 : "*",
             4 : '/',
             5 : '/',
             6 : '%',
             7 : '%',
             8 : '&',
             9 : '|',
             10 : '^',
             11 : '<<',
             12 : ">>",
             13 : 'LShR',
             14 : 'rotl',
             15 : 'rotr',
             16 : '(uint32)',
             17 : '(uint32)',
             18 : '(uint32)',
             19 : '(uint32)',
             20 : 'bswap',
             21 : "bswap",
             22 : '~',
             23 : '-',
             24 : '',
             25 : '+',
             26 : '-',
             27 : '*',
             28 : '&',
             29 : '|',
             30 : '^',
             31 : '<<',
             32 : '>>',
             33 : 'LShR',
             34 : 'rotl',
             35 : "rotr",
             36 : '(uint64)',
             37 : '(uint64)',
             38 : '(uint64)',
             39 : '(uint64)',
             40 : '(uint64)',
             41 : '(uint64)',
             42 : 'bswap',
             43 : 'bswap',
             44 : 'bswap',
             45 : '~',
             46 : '-'}

# This stuff is in target/i386/cpu.h
'''
x86_flags = {
    0xe: 0, # modify all flags, CC_DST = res, CC_SRC = src1 
    0x16 : 0, # modify all flags, CC_DST = res 
} 
'''
