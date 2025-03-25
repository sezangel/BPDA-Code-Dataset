import sys
import os
import re
import string
import binascii
import time
from collections import OrderedDict
from os.path import dirname, abspath
sys.path.append(dirname(abspath(__file__)))
import numpy as np
from copy import deepcopy as dc
import networkx as nx
from sklearn.metrics import auc, roc_curve, precision_score, recall_score, f1_score
import matplotlib.pyplot as plt
import csv
from idautils import *
import idaapi
from idaapi import *
from idc import *
import func_timeout
from opcodes import *
from features_get import *
from results_show_ida import *

from gen_pyvex_ir import *
from ida_utils import *

DEBUG = False
x86_regname_unify = {
    "al": "eax", "ah": "eax", "ax": "eax", "eax": "eax", "rax": "eax",
    "bl": "ebx", "bh": "ebx", "bx": "ebx", "ebx": "ebx", "rbx": "ebx",
    "cl": "ecx", "ch": "ecx", "cx": "ecx", "ecx": "ecx", "rcx": "ecx",
    "dl": "edx", "dh": "edx", "dx": "edx", "edx": "edx", "rdx": "edx",
    "si": "esi", "sil": "esi", "esi": "esi",
    "di": "edi", "dil": "edi", "edi": "edi",
    "ip": "eip", "eip": "eip",
    "bp": "ebp", "bpl": "ebp", "ebp": "ebp",
    "sp": "esp", "spl": "esp", "esp": "esp"
}
ret_reg_dict = OrderedDict([
    ('x86', 'eax'),
    ('x64', 'rax'),
    ('mipsbe', 'v0'),   
    ('mipsle', 'v0'),
    ('mips64be', 'v0'),
    ('mips64le', 'v0'),
    ('armbe', 'r0'),
    ('armle', 'r0'),
    ('arm64be', 'x0'),
    ('arm64le', 'x0'),
    ('ppcbe', 'r3'),
    ('ppcle', 'r3'),
    ('ppc64be', 'r3'),
    ('ppc64le', 'r3')
    ])

arg_reg_dict = OrderedDict([
    ('x86', []),
    ('x64', []),
    ('mipsbe', ['a0', 'a1', 'a2', 'a3']),
    ('mipsle', ['a0', 'a1', 'a2', 'a3']),
    ('mips64be', ['a0', 'a1', 'a2', 'a3']),
    ('mips64le', ['a0', 'a1', 'a2', 'a3']),
    ('armbe', ['R0', 'R1', 'R2', 'R3']),
    ('armle', ['R0', 'R1', 'R2', 'R3']),
    ('arm64be', ['X0', 'X1', 'X2', 'X3']),
    ('arm64le', ['X0', 'X1', 'X2', 'X3']),
    ('ppcbe', ['gpr3', 'gpr4', 'gpr5', 'gpr6', 'gpr7', 'gpr8', 'gpr9', 'gpr10']),
    ('ppcle', ['gpr3', 'gpr4', 'gpr5', 'gpr6', 'gpr7', 'gpr8', 'gpr9', 'gpr10']),
    ('ppc64be', ['gpr3', 'gpr4', 'gpr5', 'gpr6', 'gpr7', 'gpr8', 'gpr9', 'gpr10']),
    ('ppc64le', ['gpr3', 'gpr4', 'gpr5', 'gpr6', 'gpr7', 'gpr8', 'gpr9', 'gpr10'])
    ])

def find_start_block(succs, path, prev = [], block_id = 0): 
    start = None
    
    
    func_start_succs = succs[block_id]
    
    
    if block_id in prev:
        return
    
    
    for node in func_start_succs:
        if node in path:
            return node
    prev.append(block_id)
    for node in func_start_succs:
        start = find_start_block(succs, path, prev, node)
        if start != None:
            return start

def get_order_path(loops, blocks):

    loop_start = []
    succs = get_block_succs(blocks)
    
    for path in loops:
        start_node_id = find_start_block(succs, path, [])
        loop_start.append(start_node_id)
    
    new_loops = []
    i = 0
    for st in loop_start:
        if st not in loops[i]:
            continue
        st_index = loops[i].index(st)
        temp_path = loops[i][st_index:] + loops[i][0:st_index]
        new_loops.append(temp_path)
        i += 1

    return new_loops

def stack_variable_defination(stmt_str,stack_variable,dst,data_pairs):
    pattern_offset = r'Add32\(t\d+,\s*(0x[a-fA-F0-9]+)\)'
    pattern_src= r'Add32\((t\d+),'
    match_offset = re.search(pattern_offset, stmt_str)
    
    
    if match_offset:
        stack_offset=match_offset.group(1)
        
        
        if ('0xffff' in stack_offset):
        
            if(stack_offset not in stack_variable[0]):
                stack_variable[0].append(stack_offset)
                stack_variable[1].append([dst])
            else:
                index=stack_variable[0].index(stack_offset)
                stack_variable[1][index].append(dst)
            return stack_variable,0
        else:
            return stack_variable,1
    else:
        return stack_variable,1

def stack_variable_replace(data_pairs,ST_node,LD_node,ADD_node,LD_ST_order,stack_variable):
    for i in range(0,len(stack_variable[1])):
        for j in range(0,len(stack_variable[1][i])):
            LD_node=['stack%s'%str(i) if node==stack_variable[1][i][j] else node for node in LD_node]
            ST_node=['stack%s'%str(i) if node==stack_variable[1][i][j] else node for node in ST_node]
            LD_ST_order=['stack%s'%str(i) if node==stack_variable[1][i][j] else node for node in LD_ST_order]
            ADD_node=['stack%s'%str(i) if node==stack_variable[1][i][j] else node for node in ADD_node]
            data_pairs=[tuple('stack%s'%str(i) if node==stack_variable[1][i][j] else node for node in t) for t in data_pairs]
    
    return data_pairs,ST_node,LD_node,ADD_node,LD_ST_order  

def function_args(func):  
    cfunc=idaapi.decompile(func)
    if(cfunc):
        lvars = cfunc.get_lvars()
        arg_list=[]
        for i in cfunc.argidx:
            tinfo = lvars[i].type()
            name=lvars[i].name
            arg_list.append((name,tinfo))
        rettype = cfunc.type.get_rettype()
        return arg_list,rettype

def split_irsb_dst_src(irsb):
    data_pairs = []
    LD_node  = []
    ST_node = []
    ADD_node = []
    LD_first_flag = False
    CMP_flag = False
    LD_ST_order = []

    pattern=re.compile(r'offset=\d+')
    arch  = get_arch()
    stack_variable=[[],[]] 
    for _, stmt in enumerate(irsb.statements):  
        if DEBUG:
            print(str(stmt))
        match=pattern.search(str(stmt))
        if isinstance(stmt, pyvex.stmt.Put):
            
            stmt_str = "{}".format(irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(irsb.tyenv) // 8))
        elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
            
            stmt_str = "{}".format(irsb.arch.translate_register_name(stmt.data.offset, stmt.data.result_size(irsb.tyenv) // 8))
        elif isinstance(stmt, pyvex.stmt.Exit):
            
            stmt_str = "{}".format(irsb.arch.translate_register_name(stmt.offsIP, irsb.arch.bits // 8))
        else:
            
            stmt_str = stmt.__str__()
        if match:
            stmt_str=str(stmt)[:match.start()]+stmt_str+str(stmt)[match.end():]

        if "IMark" in stmt_str:
            CMP_flag = False
        if 'Cmp' in stmt_str:
            CMP_flag = True
        if CMP_flag:
            continue
        if "cc_" in stmt_str or "pc" in stmt_str or "ip" in stmt_str or 'ra' in stmt_str:
            continue
        if '=' in stmt_str and 'Cond' not in stmt_str:
            
            dst_str, src_str = [x.strip(' ') for x in stmt_str.split('=')]
            
            
            dst = filter_vex_str_dst(dst_str)
            
            if dst != None:
                src = filter_vex_str_src(src_str)
                
                if(type(src)!=list):                    
                    if arch == 'x86':
                        try:
                            dst = x86_regname_unify[dst]
                        except:
                            pass
                        try:
                            src = x86_regname_unify[src]
                        except:
                            pass
                    if "0x" in src:
                        continue
                    if "(" not in stmt_str:
                        data_pairs.append((src, dst))
                    else:
                        data_pairs.append((dst, src))
                else:
                    for i in range(0,len(src)):
                        if arch == 'x86':
                            try:
                                dst = x86_regname_unify[dst]
                            except:
                                pass
                            try:
                                src = x86_regname_unify[src[i]]
                            except:
                                pass
                        if "0x" in src:
                            continue
                        if "(" not in stmt_str:
                            data_pairs.append((src[i], dst))
                        else:
                            data_pairs.append((dst, src[i]))
            if "ST" in stmt_str:
                ST_node.append(dst)
                LD_ST_order.append(dst)
            if "LD" in stmt_str:                        
                if len(ST_node) == 0:
                    LD_first_flag = True
                LD_node.append(src)
                LD_ST_order.append(src)
            if "Add" in stmt_str or "Sh" in stmt_str:
                
                if arch == 'x86':
                    stack_variable,flag=stack_variable_defination(stmt_str,stack_variable,dst,data_pairs)
                    if flag:
                        
                        ADD_node.append(dst)
                else:
                    ADD_node.append(dst)
        else:
            continue
    if(arch=='x86'):
        
        data_pairs, ST_node, LD_node, ADD_node, LD_ST_order=stack_variable_replace(data_pairs,ST_node,LD_node,ADD_node,LD_ST_order,stack_variable)  
    return data_pairs, ST_node, LD_node, ADD_node, LD_first_flag, LD_ST_order

def if_cycle_reach_ST(ST_node,res,data_flow,LD_ST_order):
    ST_node_new=[]
    for i in range(0,len(ST_node)):
        break_flag=False
        for j in range(0,len(res)):
            for k in range(0,len(res[j])):
                
                find_path=list(nx.all_simple_paths(data_flow, res[j][k], ST_node[i]))
                if(find_path != []):
                    
                    ST_node_new.append(ST_node[i])
                    break_flag=True
                    break
            if break_flag:
                break
    
    ST_difference=list(set(ST_node).difference(set(ST_node_new)))
    
    for i in range(0,len(ST_difference)):
        LD_ST_order.remove(ST_difference[i])
    return ST_node_new,LD_ST_order

def confidence_evaluation_stripped(funcname,arg_list,ret_type):
    score=0
    len_score=40-(3-len(arg_list))*10
    if(len_score>40):
        len_score=40
    score+=len_score
    for name, tinfo in arg_list:
        if 'ptr' in str(tinfo) or '&' in str(tinfo) or '*' in str(tinfo):
            score+=30
            break
    if 'void' not in str(ret_type):
        score += 30  
    return score

def confidence_evaluation(funcname, arg_list,ret_type):
    score=0
    stripped=False
    if 'sub_' in funcname:
        stripped=True
    if stripped:
        score=confidence_evaluation_stripped(funcname,arg_list,ret_type)
        return score
    else:
        if any(keyword in funcname.lower() for keyword in ['copy', 'memcpy', 'clone', 'duplicate','string','decode','encode']):
            score += 30
        len_score=30-(3-len(arg_list))*10
        if(len_score>30):
            len_score=30
        score+=len_score
        for name, tinfo in arg_list:
            if 'ptr' in str(tinfo) or '&' in str(tinfo) or '*' in str(tinfo):
                score+=20
                break
        if 'void' not in str(ret_type):
            score += 20
        return score

def is_copy_func_with_vex(func, blocks):        
    flag = 0
    loops = []
    res = []
    succs = get_block_succs(blocks)
    if DEBUG:
        print('succs:',succs)      

    
    order_flag = True   
    
    path_thresh = 8    
    call_thresh = 2     
    inst_thresh = 20    
    loose = True
    if loose:
        store_thresh =  50  
        load_thresh = 50    
    else:
        store_thresh = 3   
        load_thresh = 3     

    start_block_ea = 0
    res=None
    G = nx.DiGraph()
    for i in range(len(succs)):
        for id in succs[i]:
            G.add_edge(i, id)
    try:
        block_loop=func_timeout.func_timeout(20,nx.simple_cycles,args=[G])
        res = list(block_loop) 
        
    except:
        pass
    if res == [] or res == None:   
        return 0, 0

    for i in range(0,len(res)):    
        loops.append(res[i])
    if DEBUG: 
        print(loops,len(loops))
    
    if len(loops) > 100:     
        return 0, 0
    if loops != []:
        
            
        loops = get_order_path(loops, blocks)  
        
            
            
        index=0
        for path in loops:      
            plt.clf()
            index=index+1
            
                
            add_flag = 0
            ADD_node_loop = []
            
            inst_nums = 0
            ix = path[0]
            start_ea = blocks[ix][0]
            start_block_ea = start_ea     
            for ix in path:
                start_ea = blocks[ix][0]
                
                    
                end_ea = blocks[ix][1]
                addr_list = list(Heads(start_ea, end_ea))
                inst_nums += len(addr_list)                
            
                
                
            
            
            
            
                
                
            ix = path[0]
            start_ea = blocks[ix][0]
            end_ea = blocks[ix][1]
            call_times = 0
            
            loop_irsb, call_times = get_block_vex_whole(start_ea, end_ea, True)
            
            for i in range(1, len(path)):
                ix = path[i]
                start_ea = blocks[ix][0]
                end_ea = blocks[ix][1]
                
                temp_isrb, temp_times = get_block_vex_whole(start_ea, end_ea, True)
                
                loop_irsb.extend(temp_isrb)
                call_times += temp_times  
            
                
                
                
            data_pairs, ST_node, LD_node, ADD_node, LD_first_flag, LD_ST_order = split_irsb_dst_src(loop_irsb)
            
            if DEBUG:
                
                print(data_pairs, ST_node, LD_node, ADD_node, LD_first_flag, LD_ST_order)
            '''if call_times > call_thresh:
                
                continue'''
            '''if call_times != 0:
                arch = get_arch()
                args_reg_list = arg_reg_dict[arch]
                ret_reg = ret_reg_dict[arch]
                for arg_reg in args_reg_list:
                    data_pairs.append((ret_reg, arg_reg))'''
            
            '''         
            if LD_first_flag == False and order_flag:  
                
                continue
            '''
            if ST_node == [] or LD_node == [] or ADD_node == []:
                
                continue        
            if len(ST_node) > store_thresh or len(LD_node) > load_thresh:
                
                continue
            data_flow = nx.DiGraph()
            for (dst, src) in data_pairs:
                if isinstance(src, tuple):
                    data_flow.add_edge(src[0], dst)
                    data_flow.add_edge(src[1], dst)
                else:
                    data_flow.add_edge(src, dst)
            nx.draw(data_flow,with_labels=True)
            
            try:
                loop_data_flow=nx.simple_cycles(data_flow)
                res = list(loop_data_flow) 
                
            except:
                
                continue
            
            if len(res)>100:
                continue
            if res == []:   
                continue
            for path in res:
                for nd in path:
                    if nd in ADD_node:
                        ADD_node_loop.append(nd)
            
                
            
            
            ST_node,LD_ST_order=if_cycle_reach_ST(ST_node,res,data_flow,LD_ST_order)
            
            for start in LD_node:
                for end in ST_node:
                    '''
                    if order_flag and LD_ST_order.index(start) >= LD_ST_order.index(end):  
                        continue
                    '''
                    start_prev = set(data_flow.predecessors(start))  
                    end_prev = set(data_flow.predecessors(end))  
                    
                        
                        
                    if start_prev & end_prev != set() and (len(start_prev) == 1 or len(end_prev) == 1):
                        
                        continue    
                    
                    ld_st_path_ger = nx.all_simple_paths(data_flow, start, end)  
                    st_ld_path_ger = nx.all_simple_paths(data_flow, end, start)
                    st_ld_path = list(st_ld_path_ger)
                    ld_st_path = list(ld_st_path_ger)
                    
                    if ld_st_path != [] and st_ld_path == []:
                        
                            
                        if ADD_node_loop == []:
                            for nd in ADD_node:
                                if nd in ld_st_path[0]:
                                    flag = 1
                                    return 1, start_block_ea
                        for nd in ADD_node_loop:
                            add_st_path_ger = nx.all_simple_paths(data_flow, nd, end)
                            add_st_path = list(add_st_path_ger)
                            
                                
                            
                            if add_st_path != [] or nd == end:
                                flag = 1
                                
                                
                                
                                
                                return 1, start_block_ea
            
                        
    return flag, start_block_ea

def get_single_func():              
    ea = get_screen_ea()
    func = idaapi.get_func(ea) 

    funcname = get_func_name(ea)
    
    
    blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]    
    new_blocks = []
    for bb in blocks:
        if is_inBlock(bb[0], func.start_ea, func.end_ea) and is_inBlock(bb[1], func.start_ea, func.end_ea + 1):  
            new_blocks.append(bb)
    blocks = new_blocks
    blocks_hex=[]
    for i in range(0,len(blocks)):
        blocks_hex.append((hex(blocks[i][0]),hex(blocks[i][1])))
    if DEBUG:
        print("blocks:",blocks_hex)
    
    flag, start_block_ea = is_copy_func_with_vex(func, blocks)
    if flag == 0:
        print("[-] False (0).")
    else:
        print("[+] True (1).")
    if(flag==1):
        arg_list,ret_type=function_args(func)
        score=confidence_evaluation(funcname,arg_list,ret_type)*0.5+50
        print('confidence score:'+str(score)+'%')
    
def get_all_func():
    file=open('result-loop.csv','w',newline='')
    write=csv.writer(file)
    write.writerow(['funcname','is loop?(0/1)','confidence score'])
    index=1
    for func_ea in idautils.Functions():
        try:
            func=idaapi.get_func(func_ea)
            
            funcname = get_func_name(func_ea)
            print(funcname,index)
            if(func.end_ea-func.start_ea>0x1000):                              
                flag=0
                score=0
                write.writerow([funcname, str(flag), str(score)+'%'])
                continue
            blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]    
            new_blocks = []
            for bb in blocks:
                if is_inBlock(bb[0], func.start_ea, func.end_ea) and is_inBlock(bb[1], func.start_ea, func.end_ea + 1):  
                    new_blocks.append(bb)
            blocks = new_blocks
            if(len(blocks)>200):                                                
                flag=0
                score=0
                write.writerow([funcname, str(flag), str(score)+'%'])
                continue
            flag, start_block_ea = is_copy_func_with_vex(func, blocks)
            if(flag==1):
                arg_list,ret_type=function_args(func)
                score=confidence_evaluation(funcname,arg_list,ret_type)*0.5+50
                print('confidence score:'+str(score)+'%')
            if(flag==0):
                score=0
            write.writerow([funcname, str(flag), str(score)+'%'])
            index+=1
        except Exception as e:
            print(e)
            index+=1
            continue
get_all_func()