def is_subsequence(main_list, sub_list):
    """检查sub_list是否是main_list的子序列"""
    it = iter(main_list)
    return all(item in it for item in sub_list)

def find_matching_paths(main_paths, path_sequences):
    """查找路径序列列表中是否存在于主路径列表中的子序列"""
    matching_paths = []
    
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

main_paths = [
    ['0x00457cd0', 'strcpy', '0x00457d14'],
    ['0x0045d4e4', '0x00457cd0', '0x0045d574'],
    ['0x00458358', '0x0045d4e4', '0x0045d888'],
    ['0x00458388', '0x00458358', '0x00458658'],
    ['0x0045868c', '0x00458388', '0x004586ac'],
    ['0x00467600', '0x0045868c', '0x004677a0'],
    ['0x0043d554', '0x00467600', '0x00443f34'],
    ['0x0043189c', '0x0043d554', '0x0043196c'],
    ['0x00431f5c', '0x0043189c', '0x00431fe8'],
    ['0x0042f40c', '0x00431f5c', '0x0042f44c'],
    ['0x00462abc', '0x0042f40c', '0x00462e28'],
    ['0x004660e0', '0x00462abc', '0x004661c4'],
    ['0x00466278', '0x004660e0', '0x0046632c'],
    ['0x00469df4', '0x00466278', '0x0046a0cc'],
    ['0x0042c920', '0x00469df4', '0x0042c9e4'],
    ['0x00406bcc', '0x0042c920', '0x00406cec'],
    ['0x00422230', '0x00406bcc', '0x00422554']
]

path_sequences = [
        [['0x00458388', '0x00458358', '0x00458658'],
     ['a', 'b', 'c']],[
     ['0x0045d4e4', '0x00457cd0', '0x0045d574'],
     ['0x00458358', '0x0045d4e4', '0x0045d888']]

]

matching_paths = find_matching_paths(main_paths, path_sequences)

print(matching_paths)