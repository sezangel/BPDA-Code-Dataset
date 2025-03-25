
import ida_name
import idautils
import ida_hexrays
import ida_funcs
import idc
import ida_ua
import ida_idp
import ida_nalt
import ida_xref
import ida_bytes
import networkx as nx
from collections import deque
import csv
import re
from loguru import logger
import sys
import concurrent.futures
from tqdm import tqdm
import time

logger.remove(handler_id=None)

level = "INFO"
debug = False

logger.add(sink=sys.stdout, level=level)

def get_function_start_address(function_name):
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if name == function_name:
            return hex(ea)
    return None

def func_name_to_addr(func_name):
    if('FUN_' in func_name):
        return '0x'+func_name[4:]
    else:
        return get_function_start_address(func_name)

def is_inBlock(ea, start, end):
    if ea >= start and ea < end:
        return True
    else:
        return False

def find_all_paths(graph,start,end):
    if start==end:
        return [[start]]
    return list(nx.all_simple_paths(graph,start,end))

def find_shortest_path(graph,start,end):
    if start==end:
        return[[start]]
    return [nx.shortest_path(graph,start,end)]

def begin_call(string_list,callee_name):
    match=re.search(r'Referencedat(\w+)', string_list[0])
    result=[func_name_to_addr(match.group(1)),callee_name,string_list[1]]
    return result

def get_block_succs(blocks):  
    succs = []
    for i in range(len(blocks)):
        succs.append([])

    for i in range(len(blocks)):
        bb_start = blocks[i][0]
        refs = CodeRefsTo(bb_start, 1)      
        logger.debug(refs)
        for ref in refs:
            for j in range(len(blocks)):
                if is_inBlock(ref, blocks[j][0], blocks[j][1]):
                    succs[j].append(i)
    return succs

def blocks_index_get(addr,blocks):
    for i in range(0,len(blocks)):
        if(int(blocks[i][0],16)<=int(addr)<int(blocks[i][1],16)):
            return i

def get_ctree(ea):
    f = idaapi.get_func(ea)
    if not f:
        logger.debug("Function not found at address: 0x%x" % ea)
        return None
    cfunc = idaapi.decompile(f)
    if not cfunc:
        logger.debug("Failed to decompile function at address: 0x%x" % ea)
        return None
    return cfunc

def find_insn_by_ea(cfunc, target_ea): 
    class MyVisitor(idaapi.ctree_visitor_t):
        def __init__(self, cfunc, target_ea):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
            self.cfunc = cfunc
            self.target_ea = target_ea
            self.target_node = None

        def visit_insn(self, insn):
            if insn.ea == self.target_ea:
                self.target_node = insn
                return 1  
            return 0
    visitor = MyVisitor(cfunc, target_ea)
    visitor.apply_to(cfunc.body, None)
    return visitor.target_node

def decompile_addr_code(code_addr): 
    cfunc = get_ctree(int(code_addr,16))
    if not cfunc:
        return
    target_node = find_insn_by_ea(cfunc, int(code_addr,16))
    if not target_node:
        logger.debug("Instruction not found at address: %s" % code_addr)
        return None
    insn_str = idaapi.tag_remove(target_node.print1(None))
    logger.debug("Instruction at address %s: %s" % (code_addr, insn_str))
    return insn_str

def extract_call_relationships(call_string):  
    call_string=call_string.replace('\n','').replace(' ','')
    parts = call_string.split("->")
    logger.debug(f"parts->{parts}")
    if(len(parts)==2):
        func_string=parts[0]
        string_list=func_string.split('>>')
        logger.debug(string_list)
        if(len(string_list)>2):
            call_relationships=[[func_name_to_addr(string_list[-2]),parts[-1],string_list[-1]]]   
            
            call_relationships.append(begin_call(string_list,func_name_to_addr(string_list[2])))
        else:
            call_relationships=[begin_call(string_list,parts[1])]
        return call_relationships
    elif(len(parts)>2):
        func_list=[]
        for i in range(1,len(parts)-1):
            string_list=parts[i].split('>>')
            logger.debug(string_list)
            for i in range(0,len(string_list)):
                if 'FUN_' in string_list[i] or '0x' not in string_list[i]:
                    func_list.append([func_name_to_addr(string_list[i]),string_list[i+1]])
        func_list.append([parts[-1]])
        call_relationships=[]
        for item in reversed(func_list[:-1]):
            call_relationships.append([item[0],func_list[func_list.index(item)+1][0],item[1]])
        call_relationships.append(begin_call(parts[0].split('>>'),func_name_to_addr(parts[1].split('>>')[0])))
        return call_relationships

def sink_strcpy_arg_extract(sink_addr):
    class StrcpyVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self, ea, cfunc):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.ea = ea
            self.cfunc = cfunc
            self.src_varname = None
            self.dst_varname = None

        def visit_expr(self, expr):
            
            if expr.op == ida_hexrays.cot_call:
                
                func_ea = expr.x.obj_ea
                func_name = idaapi.get_func_name(func_ea)
                
                if func_name == "strcpy":
                    
                    if len(expr.a) == 2:
                        dst_expr = expr.a[0]  
                        src_expr = expr.a[1]  
                        
                        if dst_expr.op == ida_hexrays.cot_var:
                            self.dst_varname = self.cfunc.lvars[dst_expr.v.idx].name
                        
                        if src_expr.op == ida_hexrays.cot_var:
                            self.src_varname = self.cfunc.lvars[src_expr.v.idx].name
                        return 1  
            return 0
    cfunc=ida_hexrays.decompile(sink_addr)
    visitor = StrcpyVisitor(sink_addr, cfunc)
    visitor.apply_to(cfunc.body, None)
    return visitor.src_varname

def variable_extract(func_addr):  
    func = ida_funcs.get_func(func_addr)
    if func is None:
        return None
    else:
        cfunc=idaapi.decompile(func_addr)
        if cfunc is None:
            return None
        else:
            target_var=[]
            var_list=[]
            for i, arg in enumerate(cfunc.arguments):
                target_var.append(arg.name)
            for lvar in cfunc.lvars:
                if lvar.name:
                    var_list.append(lvar.name)
        var_list=[item for item in var_list if item not in target_var]
        return target_var,var_list

def func_path_get(code_addr):   
    func=idaapi.get_func(code_addr)
    blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
    new_blocks=[]
    blocks_hex=[]
    blocks_thresh=20   
    for bb in blocks:
        if is_inBlock(bb[0], func.start_ea, func.end_ea) and is_inBlock(bb[1], func.start_ea, func.end_ea + 1):  
            new_blocks.append(bb)
    blocks = new_blocks
    for i in range(0,len(blocks)):
        blocks_hex.append((hex(blocks[i][0]),hex(blocks[i][1])))
    logger.debug(blocks_hex)
    code_block_index=blocks_index_get(code_addr,blocks_hex)
    blocks_number=len(blocks_hex)
    succs = get_block_succs(blocks)   
    G = nx.DiGraph()
    for i in range(len(succs)):
        for id in succs[i]:
            G.add_edge(i, id)
    if(blocks_number < blocks_thresh):
        block_path=find_all_paths(G,0,code_block_index)  
    else:
        
        return None
    logger.debug(f'block_path->{block_path}')
    func_path_all=[]
    for i in range(0,len(block_path)):   
        func_path=[]
        for j in range(0,len(block_path[i])):
            if block_path[i][j]!=code_block_index:
                begin_address=int(blocks_hex[block_path[i][j]][0],16)
                end_address=int(blocks_hex[block_path[i][j]][1],16)
                while begin_address<end_address:
                    func_path.append(hex(begin_address))
                    begin_address+=4
            else:
                begin_address=int(blocks_hex[block_path[i][j]][0],16)
                while begin_address<code_addr:
                    func_path.append(hex(begin_address))
                    begin_address+=4
        func_path=func_path[::-1]
        func_path_all.append(func_path)
    logger.debug(f'func_path_all->{func_path_all}')
    code_path_all=[]
    for i in range(0,len(func_path_all)):    
        code_path=[]
        for j in range(0,len(func_path_all[i])):
            code=decompile_addr_code(func_path_all[i][j])
            if code:
                code_test_list=code.split(';')
                code_test_list=list(filter(None,code_test_list))
                logger.debug(code_test_list)
                if len(code_test_list)==1:
                    code_path.append(code)
                else:
                    continue
            else:
                continue
        code_path_all.append(code_path)
    logger.debug(code_path_all)
    return code_path_all

def extract_vars(expression, var_list):
    """提取表达式中的变量，并参考变量列表"""
    all_vars = re.findall(r'\b\w+\b', expression)
    return [var for var in all_vars if var in var_list]

def is_related(var, expression, var_list):
    """检查变量是否与表达式中的变量有关"""
    vars_in_expr = extract_vars(expression, var_list)
    logger.debug('vars_in_expr', vars_in_expr)
    return var in vars_in_expr

def trace_variable(code_list, initial_var, var_list, target_var):  
    def recursive_trace(var, visited, processed_lines, independent):
        
        
        
        visited.add(var)
        
        for line_index in range(len(code_list)):
            
            
            line = code_list[line_index]
            
            if independent:
                if line_index in processed_lines.get(var, set()):  
                    continue
                processed_lines.setdefault(var, set()).add(line_index)
            else:
                if line_index in processed_lines.get(var, set()):
                    continue
                processed_lines.setdefault(var, set()).add(line_index)
            
            if is_related(var, line, var_list):
                vars_in_line = extract_vars(line, var_list)
                new_vars = [v for v in vars_in_line if v != var]
                new_vars=list(set(new_vars))
                
                if not new_vars:
                    for i in range(0,len(target_var)):
                        if target_var[i] in line:
                            return True
                else:
                    new_processed_lines = {v: set(processed_lines.get(v, set())) for v in var_list} 
                    for new_var in new_vars:
                        new_processed_lines[new_var] = set(processed_lines.get(var, set())) 
                        if recursive_trace(new_var, visited, new_processed_lines, len(new_vars) > 1):
                            return True
        return False

    
    processed_lines = {v: set() for v in var_list}
    return recursive_trace(initial_var, set(), processed_lines, False)

def src_arg_extract(call_relationships,call_list):  
    call_code=decompile_addr_code(call_relationships[1][2])
    match=re.search(r'Param\s*"([^"]+)"',call_list)
    param=match.group(1)
    logger.debug(f'call_code->{call_code}')
    if call_code:
        if param in call_code:
            match=re.search(r'\b\w+\s*\((.*)\)',call_code)
            if match:
                params_str=match.group(1)
                logger.debug(f'params_str->{params_str}')
                params=[param.strip() for param in params_str.split(',')]
                try:
                    param_index=params.index('"'+param+'"')
                    return param_index
                except:
                    return None
        else:
            return None
    else:
        return None

def is_related_to_target_first(sink_address,param_index):  
    
    code_path_all=func_path_get(sink_address) 
    logger.debug(f'code_path_all->{code_path_all}')
    target_var,var_list=variable_extract(sink_address)
    logger.debug(f'target_var->{target_var},param_index->{param_index}')   
    if param_index:
        try:
            target_var=[target_var[param_index]]
        except:
            pass
    logger.debug(f'target_var->{target_var}, var_list->{var_list}')

    initial_var=sink_strcpy_arg_extract(sink_address)
    logger.debug(f'initial_var->{initial_var}')

    result_flag=False
    if not initial_var:  
        result_flag=True

    if code_path_all==None: 
        result_flag=True
        return result_flag

    if not param_index and initial_var in target_var:  
        result_flag=True
        return result_flag

    if code_path_all==[[]] and param_index:  
        return False

    if len(target_var)==0: 
        result_flag=False

    for i in range(0,len(code_path_all)): 
        single_path_result=trace_variable(code_path_all[i], initial_var, var_list, target_var)
        if single_path_result:
            result_flag=True
            break
    
    return result_flag

def param_extract():  
    file=open('result-libc.txt')
    call_list=file.readlines()
    param_list=[]
    for i in range(0,len(call_list)):
        match=re.search(r'\[Param\s+"([^"]+)"', call_list[i])
        if match:
            param_name=match.group(1)
            if param_name not in param_list:
                param_list.append(param_name)
    return param_list

def if_code_have_param(param_list,call_code):
    param_patterns = [re.compile(r'\b' + re.escape(param) + r'\b') for param in param_list]
    if call_code:
        found_params = [param for param, pattern in zip(param_list, param_patterns) if pattern.search(call_code)]
        if found_params:
            return found_params
        else:
            return None
    else:
        return None

def is_related_to_target_last(param_list, call_list, call_addr): 
    call_code=decompile_addr_code(call_addr)
    match=re.search(r'Param\s*"([^"]+)"',call_list)
    param_record=match.group(1)
    param_code=if_code_have_param(param_list, call_code)
    logger.debug(f'param_record->{param_record},param_code->{param_code}')
    if param_code:
        if param_code[0]!=param_record and len(param_code)==1:
            return False
        else:
            return True
    else:
        return True

def is_related_to_target_normal(func_address): 
    target_var,var_list=variable_extract(func_address)
    logger.debug('target_var, var_list',target_var,var_list)
    result_flag=True
    if len(target_var)==0: 
        result_flag=False
    return result_flag

def is_subsequence(main_list, sub_list):
    it = iter(main_list)
    return all(item in it for item in sub_list)

def find_matching_paths(main_paths, path_sequences):    
    for path_group in path_sequences:
        group_match = True
        for path in path_group:
            path_set = set(path)
            match_found = False
            for main_path in main_paths:
                main_path_set = set(main_path)
                if path_set <= main_path_set and is_subsequence(main_path, path):
                    match_found = True
                    break
            if not match_found:
                group_match = False
                break
        if group_match:
            return True
    return False

if __name__ == '__main__':
    file=open('result-libc.txt')
    call_list=file.readlines()
    file.close()
    call_list_strcpy=[]
    call_list_other=[]
    filter_result=[]
    filter_no_result=[]
    for i in range(0,len(call_list)):
        if('Param' in call_list[i] and 'strcpy' in call_list[i]):
            call_list_strcpy.append(call_list[i])
        elif('Param' in call_list[i] and 'strcpy' not in call_list[i]):
            call_list_other.append(call_list[i])
    param_list=set(param_extract())
    logger.debug(f'param_list->{param_list}')

    first_no_list=[]
    path_no_list=[]
    no_arg_func_list=set()
    
    for i in tqdm(range(0,len(call_list_strcpy)), desc="Processing calls", unit="call"):  
        try:                   
            call_relationships=extract_call_relationships(call_list_strcpy[i])
            logger.debug(f'call_relationships->{call_relationships}')
            if(len(call_relationships)==1):  
                result_last=is_related_to_target_last(param_list, call_list_strcpy[i], call_relationships[-1][2])
                if result_last:
                    filter_result.append(call_list_strcpy[i])
                else:
                    filter_no_result.append(call_list_strcpy[i])

            elif(len(call_relationships)==2): 
                param_index=src_arg_extract(call_relationships,call_list_strcpy[i])
                logger.debug(f'param_index->{param_index}')
                if param_index:  
                    result_first=is_related_to_target_first(int(call_relationships[0][2],16),param_index)
                else:
                    result_first=is_related_to_target_first(int(call_relationships[0][2],16),None)
                result_last=is_related_to_target_last(param_list, call_list_strcpy[i], call_relationships[-1][2])
                logger.debug(f'result_first->{result_first},result_last->{result_last}')
                if result_first and result_last:
                    filter_result.append(call_list_strcpy[i])
                else:
                    filter_no_result.append(call_list_strcpy[i])

            else:  
                caller_func_list=[caller[0] for caller in call_relationships]
                if call_relationships[0][2] in first_no_list or set(caller_func_list) & no_arg_func_list: 
                    filter_no_result.append(call_list_strcpy[i])
                    continue
                result_first=is_related_to_target_first(int(call_relationships[0][2],16),None) 
                result_last=is_related_to_target_last(param_list, call_list_strcpy[i], call_relationships[-1][2])
                logger.debug(result_first)
                if result_first and result_last:
                    flag=True
                    for j in range(1,len(call_relationships)-1):
                        if(is_related_to_target_normal(int(call_relationships[j][2],16))): 
                            continue
                        else:
                            no_arg_func_list.add(call_relationships[j][0])
                            flag=False
                            
                            break
                    if flag:
                        filter_result.append(call_list_strcpy[i]) 
                    else:
                        filter_no_result.append(call_list_strcpy[i])
                else:
                    first_no_list.append(call_relationships[0][2]) 
                    filter_no_result.append(call_list_strcpy[i]) 
                    continue
        except:
            continue
    print(no_arg_func_list)
    
    '''for i in range(0,len(call_list_other)):
        call_relationships=extract_call_relationships(call_list_other[i])
        logger.debug('call_relationships',call_relationships)
        if(len(call_relationships)==1): 
            filter_result.append(call_list_other[i])
            result_last=is_related_to_target_last(param_list, call_list_other[i], call_relationships[-1][2])
            if result_last:
                filter_result.append(call_list_other[i])
            else:
                filter_no_result.append(call_list_other[i])

        elif(len(call_relationships)==2): 
            param_index=src_arg_extract(call_relationships,call_list_other[i])
            if param_index:  
                result_first=is_related_to_target_first(int(call_relationships[0][2],16),param_index)
            else:
                result_first=is_related_to_target_first(int(call_relationships[0][2],16),None)
            result_last=is_related_to_target_last(param_list, call_list_other[i], call_relationships[-1][2])
            if result_first and result_last:
                filter_result.append(call_list_other[i])
            else:
                filter_no_result.append(call_list_other[i])

        else:  
            flag=True
            result_last=is_related_to_target_last(param_list, call_list_other[i], call_relationships[-1][2])
            for j in range(1,len(call_relationships)-1):
                if(is_related_to_target_normal(int(call_relationships[j][2],16))):
                    continue
                else:
                    flag=False
                    break
            if flag:
                filter_result.append(call_list_other[i])
            else:
                filter_no_result.append(call_list_other[i])'''

    for i in range(0,len(call_list)):
        if('satc number:' in call_list[i]):
            satc_number=re.findall(r'\d+',call_list[i])[0]
            break

    
    logger.debug(f'filter_result:{len(filter_result)}')
    logger.debug(filter_result)
    file=open('result-traceback.txt','w')
    file.writelines(filter_result)
    file.write('satc number:'+satc_number+'\n')
    print('satc number:',satc_number)
    no_number=int(satc_number)-len(filter_result)
    file.write('no number:'+ str(no_number)+'\n')
    print('no number:',no_number)
    file.write('improvment proporation:'+str((no_number)/int(satc_number))+'\n')
    print('improvment proporation:',(no_number)/int(satc_number))
    file.close()
    file=open('result-traceback-no.txt','w')
    file.writelines(filter_no_result)
    file.close()