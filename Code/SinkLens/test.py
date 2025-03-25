import re

code_list = ['v5 = (int)(v4 + 1);', 'memset(v13, 0, sizeof(v13));', '*v4 = 0;', 'if ( !v4 )break;', 'sub_43F82C();', 'memset(v14, 0, sizeof(v14));', 'v11[3] = 0;', 'v11[2] = 0;', 'v11[1] = 0;', 'v11[0] = 0;', 'v10[3] = 0;', 'v10[2] = 0;', 'v10[1] = 0;', 'v10[0] = 0;', 'memset(v12, 0, sizeof(v12));', 'v9[1] = 0;', 'v9[0] = 0;', 'memset(v13, 0, sizeof(v13));']
code_list= ['v4 = v3;', 'if ( v3 )strcpy(v3, v1);', 'v3 = sub_405CEC(v2 + v4 + 1);', 'v2 = strlen(v1);' , 'v1=" ";' , 'v1 = a1;','v4 = test5']

initial_var = 'a1'
initial_var='v1'
var_list = ['v4', 'v5', 'v6', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13', 'v14']
var_list = ['v1', 'v2', 'v3', 'v4']
target_var = ['a2', 'a1']  

def extract_vars(expression, var_list):
    """提取表达式中的变量，并参考变量列表"""
    all_vars = re.findall(r'\b\w+\b', expression)
    return [var for var in all_vars if var in var_list]

def is_related(var, expression, var_list):
    """检查变量是否与表达式中的变量有关"""
    vars_in_expr = extract_vars(expression, var_list)
    
    return var in vars_in_expr

def trace_variable(code_list, initial_var, var_list, target_var):  
    def recursive_trace(var, visited, processed_lines, independent):
        print('visited',visited)
        
        
        visited.add(var)
        
        for line_index in range(len(code_list)):
            print('var',var)
            print('processed_lines',processed_lines)
            line = code_list[line_index]
            
            if independent:
                if line_index in processed_lines.get(var, set()):  
                    continue
                processed_lines.setdefault(var, set()).add(line_index)
            else:
                if line_index in processed_lines.get(var, set()):
                    continue
                processed_lines.setdefault(var, set()).add(line_index)
            print('processed_lines_new',processed_lines)
            if is_related(var, line, var_list):
                vars_in_line = extract_vars(line, var_list)
                new_vars = [v for v in vars_in_line if v != var]
                new_vars=list(set(new_vars))
                print('new_vars',new_vars)
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

is_related_to_target = trace_variable(code_list, initial_var, var_list, target_var)

print(f"初始变量 {initial_var} 是否与目标变量 {target_var} 有关: {is_related_to_target}")
