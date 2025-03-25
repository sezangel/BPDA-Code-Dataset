from idautils import *
import idaapi
from idaapi import *
from idc import *

import os
import sys
import time
import copy
import archinfo
import pyvex
from archinfo import Endness
from elementals import Logger
import logging
import networkx as nx
def get_vex_arch():
    inst_arch = None
    arch = idaapi.get_inf_structure().procName.lower()
    if arch in 'mipsb':
        inst_arch = archinfo.ArchMIPS32(Endness.BE) 
    elif arch in 'mipsl':
        inst_arch = archinfo.ArchMIPS32(Endness.LE) 
    elif arch in 'ppc':
        inst_arch = archinfo.ArchPPC32(Endness.BE)
    elif arch in 'ppcl':
        inst_arch = archinfo.ArchPPC32(Endness.LE)
    elif arch in 'arm':
        inst_arch = archinfo.ArchARM(Endness.LE)
    elif arch in 'armb':
        inst_arch = archinfo.ArchARM(Endness.BE)    
    elif arch in 'metapc':
        inst_arch = archinfo.ArchX86()
    return inst_arch

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
def get_func_vex_block(ea):
    '''
    @input: address
    @return: the list of function irsb
    '''
    func = idaapi.get_func(ea)
    func_name = get_func_name(ea)
    
    
    blocks = [v for v in idaapi.FlowChart(func)]

    inst_arch = get_vex_arch()
    func_irsb = []
    for bb in blocks:
        bb_start = bb.start_ea
        bb_end = bb.end_ea
        while bb_start < bb_end:
            block_bytes = ida_bytes.get_bytes(bb_start, bb_end - bb_start)
            irsb = pyvex.IRSB(block_bytes, mem_addr = bb_start, arch = inst_arch, opt_level = 1,strict_block_end= True, hwcache=False)
            func_irsb.append(irsb)
            if irsb.size == 0:
                bb_start = next_head(bb_start)
            else:
                bb_start = bb_start + irsb.size

    return func_irsb

def get_func_vex_whole(ea):
    '''
    @input: address
    @return: the irsb of whole function
    '''
    func = idaapi.get_func(ea)
    func_name = get_func_name(ea)
    
    
    blocks = [v for v in idaapi.FlowChart(func)]
    print("0x%x - 0x%x" % (func.start_ea, func.end_ea))
    new_blocks = []

    for bb in blocks:
        if is_inBlock(bb.start_ea, func.start_ea, func.end_ea) and is_inBlock(bb.end_ea, func.start_ea, func.end_ea + 1):
            new_blocks.append(bb)
    blocks = new_blocks

    inst_arch = get_vex_arch()
    func_irsb = pyvex.IRSB(None, func.start_ea, arch = inst_arch)
    for bb in blocks:
        bb_start = bb.start_ea
        bb_end = bb.end_ea
        while bb_start < bb_end:
            block_bytes = ida_bytes.get_bytes(bb_start, bb_end - bb_start)
            irsb = pyvex.IRSB(block_bytes, mem_addr = bb_start, arch = inst_arch, opt_level = 1,strict_block_end= True)
            func_irsb.extend(irsb)
            if irsb.size == 0:
                bb_start = next_head(bb_start)
            else:
                bb_start = bb_start + irsb.size
    return func_irsb

def get_block_vex_list(bb_start, bb_end):
    '''
    @input: block start address, block end address
    @return: the list of block irsb
    '''

    inst_arch = get_vex_arch()
    bb_irsb = []
    '''
    segm = idaapi.get_segm_by_name(".text")
    if bb_end > segm.end_ea:
        return bb_irsb
    '''
    
    while bb_start < bb_end:
        block_bytes = ida_bytes.get_bytes(bb_start, bb_end - bb_start)
        irsb = pyvex.IRSB(block_bytes, mem_addr = bb_start, arch = inst_arch, opt_level = 1,strict_block_end= True)
        bb_irsb.append(irsb)
        if irsb.size == 0:
            bb_start = next_head(bb_start)
        else:
            bb_start = bb_start + irsb.size
    return bb_irsb

def get_block_vex_whole(bb_start, bb_end, count_call = False):
    '''
    @input: block start address, block end address
    @return: the irsb of whole block
    '''

    
    
    call_time = 0
    inst_arch = get_vex_arch()
    bb_irsb = pyvex.IRSB(None, bb_start, arch = inst_arch)
    
    while bb_start < bb_end:
        block_bytes = ida_bytes.get_bytes(bb_start, bb_end - bb_start)
        irsb = pyvex.IRSB(block_bytes, mem_addr = bb_start, arch = inst_arch, opt_level = 1,strict_block_end= True)
        if count_call:
            if irsb.jumpkind == 'Ijk_Call':
                call_time += 1
        bb_irsb.extend(irsb)
        if irsb.size == 0:
            bb_start = next_head(bb_start)
        else:
            bb_start = bb_start + irsb.size
    if count_call:
        return bb_irsb, call_time
    
    return bb_irsb

def main():
    func_irsb = []
    ea = get_screen_ea()
    features = []

    func_irsb = get_func_vex_block(ea)
    for irsb in func_irsb:
        print(irsb)
    func_irsb = get_func_vex_whole(ea)
    print(func_irsb)
    
    
    
    
    
    '''
    func = idaapi.get_func(ea)
    blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
    new_blocks = []
    for bb in blocks:
            if is_inBlock(bb[0], func.start_ea, func.end_ea) and is_inBlock(bb[1], func.start_ea, func.end_ea + 1):
                new_blocks.append(bb)
    blocks = new_blocks
    node = 0
    succs = get_block_succs(blocks)
    '''
    '''
    for bb in blocks:
        bb_irsb = get_block_vex_list(bb[0], bb[1])
        
        features.append(get_block_features_gemini(bb_irsb, node, succs))
        node += 1
        for irsb in bb_irsb:
            func_irsb.append(irsb)
    
        
        
        
    if len(blocks) < len(func_irsb):
        print("Found implicit 'branch' instruction...")
    print(features["features"])
    funcs_features = []
    funcs_features.append(features)
    binary_name = get_root_filename() + '_vex.json'
    out = open(binary_name, "w")
    for res in funcs_features:
        res = str(res).replace('\'', '\"')
        print(res, file=out)
    out.close()

    func = idaapi.get_func(ea)
    blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
    for bb in blocks:
        bb_irsb = get_block_vex_whole(bb[0], bb[1])
        func_irsb.append(bb_irsb)
    for irsb in func_irsb:
        
        print(irsb)
    '''
    
if __name__ == '__main__':
    main()