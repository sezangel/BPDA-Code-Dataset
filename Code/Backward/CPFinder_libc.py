
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

sink_function=['strcpy','sscanf','sprintf','system','popen']    
compare_list=['strcpy','sscanf','sprintf']
type_3_list=['strcpy','memcpy']
arch_arg_mips={'strcpy':'$a1','memcpy':'$a1','sprintf':'$a1','sscanf':'$a0','system':'$a0','popen':'$a0'}
arch_arg_arm={'strcpy':'R1'}

DEBUG=False
Experiment=True
Compare=True

def is_inBlock(ea, start, end):  
    if ea >= start and ea < end:
        return True
    else:
        return False

def is_library_func(func_name):  
    func_address=ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
    func = ida_funcs.get_func(func_address)
    if func:
        return bool(func.flags & ida_funcs.FUNC_LIB)
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

def get_arch(procName):  
    if 'mips' in procName:
        return 'mips'
    elif 'arm' in procName or 'ARM' in procName:
        return 'arm'
    elif 'ppc' in procName:
        return 'ppc'
    else:
        return None

def ins_analysis(insn):             
    ins_analysis_result=[]
    ins_analysis_result.append(insn.get_canon_mnem())
    for op in insn.ops:
    
        if op.type==ida_ua.o_reg:      
            reg_name=ida_idp.get_reg_name(op.reg,op.dtype)
            ins_analysis_result.append(['reg',reg_name])
        elif op.type==ida_ua.o_mem:    
            name=idc.get_name(op.addr)
            ins_analysis_result.append(['mem',name,op.addr])
        elif op.type==ida_ua.o_displ:  
            base_reg=ida_idp.get_reg_name(op.reg, op.dtype)
            offset=op.addr
            ins_analysis_result.append(['displ',base_reg,offset])
        elif op.type==ida_ua.o_imm:    
            imm_addr=op.value
            ins_analysis_result.append(['imm',hex(imm_addr)])
    if DEBUG:
        print(ins_analysis_result)
    return ins_analysis_result

def call_function_detection(func_addr,disasm,jmp_type):   
    if jmp_type=='jalr':
        match=re.search(r'jalr\s+\$t[0-9]\s+;\s+(.*)', disasm)
        if match:
            has_call=match.group(1)
            return has_call
        return None
    if jmp_type=='jal':
        match=re.search(r'jal\s+(.*)', disasm)
        if match:
            has_call=match.group(1)
            return has_call
        return None

def trace_blocks(graph,start,depth):   
    paths=[]
    queue=deque([([start], 0)])
    if start==0:
        paths.append([0])
        return paths
    while queue:
        path, current_depth = queue.popleft()
        current_node = path[-1]
        if current_depth == depth or not list(graph.predecessors(current_node)):
            paths.append(path[::-1])
            continue
        for next_node in graph.predecessors(current_node):
            if next_node not in path:
                new_path = list(path)  
                new_path.append(next_node)
                queue.append((new_path, current_depth + 1))   
    return paths

def instruction_analysis_arm_main(blocks,block_path_all_sorted,call_ea,type_func):
    return []

def instruction_analysis_mips_main(blocks,block_path_all_sorted,call_ea,type_func):    
    print('block_path_all_sorted:',block_path_all_sorted)
    arg_reg=arch_arg_mips[type_func]
    block_path_index=0
    recall_key_list_all=[]
    for block_path in block_path_all_sorted:
        recall_key_list=['reg',arg_reg]
        ins_addr=call_ea+4
        print('block_path_index:',block_path_index)
        for block_index in block_path[::-1]:     
            if block_path.index(block_index)!=len(block_path)-1:
                ins_addr=blocks[block_index][1]-4
            break_flag=False
            break_all_flag=False
            while ins_addr >= blocks[block_index][0]:
                disasm=idc.GetDisasm(ins_addr)
                if DEBUG:
                    print('ins addr:',hex(ins_addr),disasm)
                if recall_key_list[0]=='reg' and recall_key_list[1]=='$v0' and 'jal' in disasm:     
                    if 'jalr' in disasm:         
                        print('call identified')
                        has_call=call_function_detection(ins_addr,disasm,'jalr')
                    elif 'jal' in disasm:        
                        print('call identified')
                        has_call=call_function_detection(ins_addr,disasm,'jal')
                    if has_call:
                        print('Call function:',has_call)
                        break_all_flag=True
                        recall_key_list=['function_call',has_call]
                        break
                insn=ida_ua.insn_t()
                ida_ua.decode_insn(insn, ins_addr)
                ins_analysis_result=ins_analysis(insn)
                if recall_key_list in ins_analysis_result and len(ins_analysis_result)>=3:      
                    if len(ins_analysis_result)==3:        
                        key_index=ins_analysis_result.index(recall_key_list)
                        '''if key_index==1 and ins_analysis_result[0]=='addiu' and ins_analysis_result[2][0]=='imm':  
                            pass'''
                        if recall_key_list[0]=='reg' and key_index==1 and ins_analysis_result[0]!='sw':   
                            recall_key_list=ins_analysis_result[2]
                            print(recall_key_list)
                        elif recall_key_list[0]=='displ' and key_index==2 and ins_analysis_result[0]=='sw': 
                            key_index=ins_analysis_result.index(recall_key_list)
                            recall_key_list=ins_analysis_result[1]
                            print(recall_key_list)
                    elif len(ins_analysis_result)==4:
                        recall_key_list=ins_analysis_result[2]
                        print(recall_key_list)
                ins_addr=idc.prev_head(ins_addr)
                if recall_key_list[0]=='imm':
                    break_all_flag=True
                    break_flag=True
                    break
            if break_flag:
                break
        if break_all_flag:
            recall_key_list_all.append(recall_key_list)
            break
        recall_key_list_all.append(recall_key_list)
        block_path_index+=1
    return recall_key_list_all

def result_filter_operation(recall_key_list):    
    return_flag=False
    refs_filter=[]
    white_function_list=[]
    if recall_key_list[0]=='mem':
        return_flag=False
    elif recall_key_list[0]=='function_call':
        if recall_key_list[0] in white_function_list or not(is_library_func(recall_key_list[1])):
            return_flag=True
        else:
            return_flag=False
    elif recall_key_list[0]=='imm':
        return_flag=False 
    else:
        return_flag=True
    
    return return_flag

def test_record(refs_filter,refs_no,libc_func):               
    file=open('result-libc.csv','a',newline='')
    write=csv.writer(file)
    caller_filter_num=0
    caller_all_num=0
    filter_caller_proportion=1
    filter_proportion=1
    function_filter_list=[]
    function_no_list=[]
    refs_filter_result=[]
    refs_no_result=[]
    for i in range(0,len(refs_filter)):
        number=0
        func=ida_funcs.get_func(int(refs_filter[i],16))
        func_address=func.start_ea
        func_name=ida_funcs.get_func_name(func_address)
        for xref in idautils.XrefsTo(func_address, 0):
            caller_func=ida_funcs.get_func(xref.frm)
            if caller_func:
                number+=1
        caller_filter_num+=number
        caller_all_num+=number
        if func_name not in function_filter_list:
            function_filter_list.append(func_name)
            refs_filter_result.append([func_name,libc_func,[refs_filter[i]],'1'])
        else:
            func_index=function_filter_list.index(func_name)
            refs_filter_result[func_index][2].append(refs_filter[i])
    for i in range(0,len(refs_filter_result)):
        refs_filter_result[i][2]=','.join(refs_filter_result[i][2])
        write.writerow(refs_filter_result[i])

    for i in range(0,len(refs_no)):
        number=0
        func=ida_funcs.get_func(int(refs_no[i],16))
        func_address=func.start_ea
        func_name=ida_funcs.get_func_name(func_address)
        for xref in idautils.XrefsTo(func_address, 0):
            caller_func=ida_funcs.get_func(xref.frm)
            if caller_func:
                number+=1
        caller_all_num+=number
        if func_name not in function_no_list:
            function_no_list.append(func_name)
            refs_no_result.append([func_name,libc_func,[refs_no[i]],'0'])
        else:
            func_index=function_no_list.index(func_name)
            refs_no_result[func_index][2].append(refs_no[i])
    for i in range(0,len(refs_no_result)):
        refs_no_result[i][2]=','.join(refs_no_result[i][2])
        write.writerow(refs_no_result[i])
    file.close()
    if len(refs_filter)+len(refs_no)!=0:
        filter_proportion=len(refs_filter)/(len(refs_filter)+len(refs_no))
    if caller_all_num!=0:
        filter_caller_proportion=caller_filter_num/caller_all_num
    print('filter_proportion:',filter_proportion)
    print('filter_caller_proportion',filter_caller_proportion)
    file_record=open('result-data.csv','a',newline='')    
    write=csv.writer(file_record)
    write.writerow([libc_func,len(refs_filter)+len(refs_no),len(refs_filter),caller_all_num,caller_filter_num])
    file_record.close()

def stack_variable_defination(func_code_list,number,variable):   
    for i in range(0,number):
        if variable in func_code_list[i]:
            def_end_number=len(func_code_list[i])
            if '//' in func_code_list[i]:
                def_end_number=func_code_list[i].find('//')
            arrays_pattern=re.compile(r'\[(\d+)\]')                
            arrays_length=arrays_pattern.findall(func_code_list[i][:def_end_number])
            if len(arrays_length)==1:
                return int(arrays_length[0])
            else:
                return 0
    return 0

def variable_filter(arg):         
    variable_address = idc.get_name_ea_simple(arg)        
    if variable_address == idc.BADADDR:
        return True    
    else:
        return False   

def result_deal_func_type_1(recall_key_list_all):         
    
    result_flag=True  
    print('recall_key_list_all:',recall_key_list_all)
    for j in range(0,len(recall_key_list_all)):
        return_flag=result_filter_operation(recall_key_list_all[j])
        '''if return_flag:                                 
            result_flag=True
            break'''
        if return_flag==False:                             
            result_flag=False
            break
    if result_flag:                  
        return True
    else:                            
        return False

def result_deal_func_type_2(call_ea,libc_func):              
    result_flag=False
    function = idaapi.get_func(call_ea)
    code=idaapi.decompile(function.start_ea)
    if libc_func=='sscanf':
        format_strings = re.findall(r'sscanf\s*\(\s*[^,]+,\s*"([^"]+)"',str(code))
    else:
        format_strings = re.findall(r'sprintf\s*\(\s*[^,]+,\s*"([^"]+)"',str(code))
    for format_string in format_strings:
        if '%s' in format_string:
            result_flag=True
            return result_flag
        else:
            continue
    return result_flag

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

def get_strcpy_varnames(ea):  
    
    cfunc = ida_hexrays.decompile(ea)
    if not cfunc:
        print("反编译失败")
        return None, None

    
    visitor = StrcpyVisitor(ea, cfunc)
    visitor.apply_to(cfunc.body, None)

    return visitor.dst_varname, visitor.src_varname

def result_deal_func_type_3(refs_addr,Dangerous_function):  
    if Dangerous_function not in type_3_list:
        return True
    func_code=str(ida_hexrays.decompile(refs_addr))
    src_def_length=0
    dst_def_length=0
    arg_dst, arg_src=get_strcpy_varnames(refs_addr)
    if arg_src:   
        func_code_list=func_code.split('\n')
        number=func_code_list.index('')
        
        src_def_length=stack_variable_defination(func_code_list,number,arg_src)
        
        if 0 < src_def_length < 20:      
            return False
        else:
            if arg_dst:   
                dst_def_length=stack_variable_defination(func_code_list,number,arg_dst)
                if src_def_length>0 and dst_def_length>0 and src_def_length < dst_def_length:
                    return False       
                else:
                    return True
            else:
                return True
    else:
        result=variable_filter(arg_src) 
        return result              

def Analysis_main(Dangerous_function):
    info = idaapi.get_inf_structure()
    arch=get_arch(info.procName)
    print(arch)
    addr=ida_name.get_name_ea(ida_idaapi.BADADDR, Dangerous_function)
    refs=list(idautils.CodeRefsTo(addr,0))  
    refs_hex=[]
    refs_filter=[]
    refs_no=[]
    for i in range(0,len(refs)):
        refs_hex.append(hex(refs[i]))
    if DEBUG:
        print('refs_list:',refs_hex)   
    for i in range(0,len(refs)):
        try:
            print('Refs-Index:%s  address:%s' %(str(i),hex(refs[i])))
            call_ea=refs[i]
            if DEBUG:
                print('call_ea:',hex(call_ea))
            
            func_ea=idc.get_func_attr(call_ea,idc.FUNCATTR_START)
            func = idaapi.get_func(func_ea) 
            
            blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
            if DEBUG:
                print('blocks:',blocks)
            for j in range(0,len(blocks)):
                if blocks[j][0]<=call_ea<blocks[j][1]:
                    block_call_ea=blocks[j][0]
                    block_call_ea_index=j
                    break
            if DEBUG:
                print('block_call_ea:',hex(block_call_ea))  
            succs = get_block_succs(blocks)
            G = nx.DiGraph()
            for j in range(len(succs)):
                for id in succs[j]:
                    G.add_edge(j, id)
            block_path_all_sorted=trace_blocks(G,block_call_ea_index,1)  
            
            
            if(len(block_path_all_sorted)>10):
                block_path_all_sorted=block_path_all_sorted[0:10]
            if DEBUG:
                print('block_path_all_sorted:',block_path_all_sorted)

            if arch=='mips':
                if Dangerous_function=='strcpy' or Dangerous_function=='memcpy' or Dangerous_function=='system' or Dangerous_function=='popen':
                    recall_key_list_all=instruction_analysis_mips_main(blocks,block_path_all_sorted,call_ea,Dangerous_function)  
                    if result_deal_func_type_1(recall_key_list_all) and result_deal_func_type_3(call_ea, Dangerous_function):   
                        print('True')
                        refs_filter.append(hex(refs[i]))
                    else:
                        print('False')
                        refs_no.append(hex(refs[i]))
                elif Dangerous_function=='sscanf':
                    recall_key_list_all=instruction_analysis_mips_main(blocks,block_path_all_sorted,call_ea,Dangerous_function)     
                    if result_deal_func_type_1(recall_key_list_all) and result_deal_func_type_2(refs[i],'sscanf'):      
                        refs_filter.append(hex(refs[i]))
                    else:
                        refs_no.append(hex(refs[i]))
                elif Dangerous_function=='sprintf':
                    if result_deal_func_type_2(refs[i],'sprintf'):      
                        refs_filter.append(hex(refs[i]))
                    else:
                        refs_no.append(hex(refs[i]))
            elif arch=='arm':
                if Dangerous_function=='strcpy' or Dangerous_function=='memcpy' or Dangerous_function=='system' or Dangerous_function=='popen':
                    recall_key_list_all=instruction_analysis_arm_main(blocks,block_path_all_sorted,call_ea,Dangerous_function)  
                    if result_deal_func_type_1(recall_key_list_all) and result_deal_func_type_3(call_ea, Dangerous_function): 
                        refs_filter.append(hex(refs[i]))
                    else:
                        refs_no.append(hex(refs[i]))
                elif Dangerous_function=='sscanf':
                    
                    if result_deal_func_type_2(refs[i],'sscanf'):       
                        refs_filter.append(hex(refs[i]))
                    else:
                        refs_no.append(hex(refs[i]))
                elif Dangerous_function=='sprintf':
                    
                    if result_deal_func_type_2(refs[i],'sprintf'):      
                        refs_filter.append(hex(refs[i]))
                    else:
                        refs_no.append(hex(refs[i]))
        except:
            continue
    
    return refs_filter,refs_no

def compare_satc():  
    file=open('result-libc.csv','r')
    rd=csv.reader(file)
    data=list(rd)
    file.close()
    libc_no_list=[]
    satc_list_filter=[]
    for i in range(0,len(data)):
        if(data[i][1] in compare_list and data[i][3]=='0'):
            addr_list=data[i][2].split(',')
            for i in range(0,len(addr_list)):
                libc_no_list.append('0x' + addr_list[i][2:].zfill(8))
    file=open('httpd_ref2sink_bof.result','r')
    satc_list=file.readlines()
    file.close()
    pattern = re.compile(r'0x[0-9a-fA-F]+(?=\s*->\s*(?:\bstrcpy\b|\bsscanf\b|\bsprintf\b|\bsystem\b|\bpopen\b))')
    
    file=open('result-libc.txt','w')
    satc_number=0
    no_number=0
    for i in range(0,len(satc_list)):
        result=pattern.findall(satc_list[i])
        
        if len(result)==1:     
            satc_number+=1
            satc_list_filter.append(result[0])
            if result[0] in libc_no_list:
                no_number+=1
            else:
                file.write(satc_list[i])
        else:
            continue
    file.write('satc number:'+str(satc_number)+'\n')  
    print('satc number:',satc_number)
    file.write('no number:'+ str(no_number)+'\n')
    print('no number:',no_number)
    file.write('improvment proporation:'+str((no_number)/satc_number)+'\n')
    print('improvment proporation:',(no_number)/satc_number)
    
    '''
    satc_number=0
    satc_list_filter=[]
    no_number=0
    for i in range(0,len(satc_list)):
        result=pattern.findall(satc_list[i])   
        if len(result)==1 and result[0] not in satc_list_filter: 
            satc_number+=1
            satc_list_filter.append(result[0])
            if result[0] in libc_no_list:
                no_number+=1
        else:
            continue
    file.write('satc number:'+str(satc_number)+'\n')  
    print('satc number:',satc_number)
    file.write('no number:'+ str(no_number)+'\n')
    print('no number:',no_number)
    file.write('improvment proporation:'+str((satc_number-no_number)/satc_number)+'\n')
    print('improvment proporation:',(satc_number-no_number)/satc_number)
    file.close()'''

if __name__ == '__main__':
    if Experiment:
        file=open('result-libc.csv','a',newline='')
        write=csv.writer(file)
        write.writerow(['function','libc_func','call_address','is Dangerous?(0/1)'])
        file.close()
        file_record=open('result-data.csv','a',newline='')
        write=csv.writer(file_record)
        write.writerow(['libc_func','func_number','filter_number','caller_number','caller_filter_number'])
        file_record.close()
        for i in range(0,len(sink_function)):    
            refs_filter,refs_no=Analysis_main(sink_function[i])
            print(refs_filter,refs_no,len(refs_filter),len(refs_no))
            record=test_record(refs_filter,refs_no,sink_function[i])
    if Compare:
        compare_satc()
    
        
    