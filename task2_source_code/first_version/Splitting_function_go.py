import os
import re

def extract_functions_with_receivers(input_directory):
    out_funtions=[]
    # 获取指定目录下的所有 .go 文件
    go_files = [f for f in os.listdir(input_directory) if f.endswith('.go')]
    
    for go_file in go_files:
        # 获取当前文件路径和文件名
        file_path = os.path.join(input_directory, go_file)
        file_name, _ = os.path.splitext(go_file)
        output_directory = os.path.join(input_directory, f"{file_name}_result")
        
        # 创建结果存储文件夹
        os.makedirs(output_directory, exist_ok=True)
        
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        # 初始化变量
        functions = []
        current_function = []
        stack = []  # 用于跟踪大括号的堆栈
        inside_function = False
        
        # 改进后的正则表达式，支持接收器和多行定义
        func_start_pattern = re.compile(r'^func\s+(\(\w+\s+\*?\w+\)\s+)?\w+\(.*\)\s*{?')
        
        for line in lines:
            if not inside_function:
                # 检测函数定义的起始
                match = func_start_pattern.match(line)
                if match:
                    inside_function = True
                    current_function.append(line)
                    
                    # 检查是否有未闭合的 `{`，如果有则记录
                    if '{' in line and '}' not in line:
                        stack.append('{')
            else:
                # 当前在函数体内，累积函数内容
                current_function.append(line)
                
                # 检查大括号，更新堆栈状态
                for char in line:
                    if char == '{':
                        stack.append('{')
                    elif char == '}':
                        if stack:
                            stack.pop()
                
                # 如果堆栈为空，函数结束
                if not stack:
                    functions.append("".join(current_function))
                    current_function = []
                    inside_function = False
        
        out_funtions+=functions
    return out_funtions
