from idautils import *
import idaapi
from idaapi import *
from idc import *
from opcodes import *

def get_unified_funcname(ea): 
    funcname = get_func_name(ea)
    if len(funcname) > 0:
        if '.' == funcname[0]:
            funcname = funcname[1:]
    return funcname

def get_all_succs_func(funcea):
    func = idaapi.get_func(funcea)
    curr_name = get_func_name(funcea)
    ea = func.start_ea
    succs = []
    succs_name = []
    while ea < func.end_ea:
        for ref in CodeRefsFrom(ea, False):
            succs.append(ref)
        
        ea = next_head(ea)
    for ea in succs:

        func_name = get_func_name(ea)
        if func_name != curr_name:
            succs_name.append(func_name)
    
    
    return succs_name

def get_features():
    binary_name = get_root_filename()
    '''
    if "clang" in binary_name:      
        copy_funcs_name.remove('strncpy')
        copy_funcs_name.remove('memccpy')
        copy_funcs_name.remove('strcat')
        copy_funcs_name.remove('strncat')
        copy_funcs_name.remove('strcpy')
        copy_funcs_name.remove('wmemcpy')
    '''
    print("binary name: %s" % binary_name)
    funcs_features = []
    segm = idaapi.get_segm_by_name(".text")
    for funcea in Functions(segm.start_ea,segm.end_ea):
        func = idaapi.get_func(funcea) 
        funcname = get_unified_funcname(funcea)

    
        if funcname.startswith("_"):
            continue
        
        blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
        new_blocks = []

        
        
        for bb in blocks:
            if is_inBlock(bb[0], func.start_ea, func.end_ea) and is_inBlock(bb[1], func.start_ea, func.end_ea + 1):
                new_blocks.append(bb)
        blocks = new_blocks
        if len(blocks) < 3:
            continue
        features = get_func_features(func, blocks)  
        funcs_features.append(features)

    return funcs_features

def get_insts_set():

    loads = set()
    stores = set()
    branch = set()
    arithmetic = set()

    loads.update(mips_load)
    loads.update(arm_load)
    loads.update(ppc_load)

    stores.update(mips_store)
    stores.update(arm_store)
    stores.update(ppc_store)

    branch.update(mips_branch)
    branch.update(arm_branch)
    branch.update(ppc_branch)

    arithmetic.update(mips_arithmetic)
    arithmetic.update(ppc_arithmetic)
    arithmetic.update(arm_arithmetic)
    arithmetic.update(x86_arithmetic)

    return loads, stores, branch, arithmetic

def is_inBlock(ea, start, end):
    if ea >= start and ea < end:
        return True
    else:
        return False

def get_block_succs(blocks):
    succs = []
    for i in range(len(blocks)):
        succs.append([])

    for i in range(len(blocks)):

        bb_start = blocks[i][0]
        refs = CodeRefsTo(bb_start, 1)      
        
        for ref in refs:
            for j in range(len(blocks)):
                if is_inBlock(ref, blocks[j][0], blocks[j][1]):
                    succs[j].append(i)

    return succs

def get_offspring(succs):
    nodes = [i for i in range(len(succs))]
    offspring_fea = []
    for node in nodes:
        offsprings = {}
        recu_offspring(succs, node, offsprings)
        offspring_fea.append(len(offsprings))
    return offspring_fea

def recu_offspring(succs, node, offsprings):
	node_offs = 0
	sucs = succs[node]
	for suc in sucs:
		if suc not in offsprings:
			offsprings[suc] = 1
			recu_offspring(succs, suc, offsprings)

def get_inst_num(ea):
    opcode = print_insn_mnem(ea)

    return opcode
def get_ea_constant(ea):
    const_nums = 0
    str_nums = 0
    for i in range(3):
        if get_operand_type(ea, i) == idaapi.o_imm: 
            const = get_operand_value(ea, i)
            if const < 10:
                return 1
    return 0

def get_func_features(func, blocks):
    
    features = {}
    succs = []
    func_feas = []
    
    flag = 0
    arch = idaapi.get_inf_structure().procName.lower()
    loads = set()
    stores = set()
    branch = set()
    succs_name = []
    arithmetic = set()
    regs = set()

    loads, stores, branch, arithmetic= get_insts_set()

    funcname = get_unified_funcname(func.start_ea)

    if funcname in copy_funcs_name:
        succs_name = get_all_succs_func(func.start_ea)
        if "memcpy" in succs_name or "strcpy" in succs_name:
            flag = 0
        else:
            flag = 1
    else:
        flag = 0

    for bb in blocks:
        bb_start = bb[0]
        bb_end = bb[1]    
        feas = [0, 0, 0, 0, 0, 0] 
        ea = bb_start

        regs = set()
        while ea < bb_end:
            opcode = print_insn_mnem(ea)

            optype0 = get_operand_type(ea, 0)
            optype1 = get_operand_type(ea, 1)
            optype2 = get_operand_type(ea, 2)

            if optype0 == 0x1:
                regs.add(print_operand(ea, 0))
            if optype1 == 0x1:
                regs.add(print_operand(ea, 1))
            if "metapc" in arch:
                if opcode in x86_move:
                    if (optype0 == 0x3 and optype1 == 0x1) or (optype0 == 0x4 and optype1 == 0x1):
                        feas[1] = feas[1] + 1
                    elif (optype0 == 0x1 and optype1 == 0x3) or (optype0 == 0x1 and optype1 == 0x4):
                        feas[0] = feas[0] + 1
                
                
                
                elif opcode in arithmetic:
                    feas[4] = feas[4] + 1
                
            else:
                if opcode in loads:
                    feas[0] = feas[0] + 1
                elif opcode in stores:
                    feas[1] = feas[1] + 1
                
                elif opcode in branch:
                    feas[2] = feas[2] + 1
                elif opcode in arithmetic:
                    if optype1 == 0x5 or optype2 == 0x5:
                        feas[4] = feas[4] + 1
                elif 'ppc' in arch and (opcode in ppc_load or opcode in ppc_store) and 'u' in opcode:
                    feas[4] = feas[4] + 1
                elif 'arm' in arch and (opcode in arm_load or opcode in arm_store):
                    if 'B' in opcode:
                        feas[4] = feas[4] + 1
                    elif '
                        feas[4] = feas[4] + 1

            feas[5] = feas[5] + 1

            ea = next_head(ea)

        feas[3] = len(regs) 
        func_feas.append(feas)
    succs = get_block_succs(blocks)
    offspring_feas = get_offspring(succs)
    for i in range(len(offspring_feas)):
        func_feas[i][2] = offspring_feas[i]
        
    features["fname"] = funcname
    features["n_num"] = len(blocks)
    features["succs"] = succs
    features["features"] = func_feas
    features["flag"] = flag

    return features