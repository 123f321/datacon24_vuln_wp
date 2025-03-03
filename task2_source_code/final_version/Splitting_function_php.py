import os
import re

def extract_php_functions_with_context(file_path):
    """
    使用栈从PHP文件中提取函数定义，支持类上下文信息
    :param file_path: PHP文件路径
    :return: 函数列表，每个元素是一个函数的完整定义
    """
    functions = []
    stack = []
    current_function = []
    inside_function = False
    class_context = []

    # 正则匹配
    function_start_pattern = re.compile(r'^function\s+\w+\s*\(.*\)\s*{')
    class_start_pattern = re.compile(r'^class\s+\w+\s*{')

    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines:
        stripped_line = line.strip()

        # 检测类定义的起始
        if class_start_pattern.search(stripped_line) and not inside_function:
            class_context.append(line)
            stack.append('{')
            continue

        # 检测函数定义的起始
        if function_start_pattern.search(stripped_line):
            # 如果当前已在记录函数，则先保存并结束
            if current_function:
                functions.append(''.join(class_context + current_function))
                current_function = []

            inside_function = True
            current_function.append(line)  # 记录函数起始行
            stack.append('{')  # 函数起始，压栈
            continue

        # 如果已进入函数定义，记录内容
        if inside_function:
            current_function.append(line)
            # 检测大括号的开闭
            for char in line:
                if char == '{':
                    stack.append('{')
                elif char == '}':
                    if stack:
                        stack.pop()

            # 栈为空时，函数结束
            if not stack:
                functions.append(''.join(class_context + current_function))
                current_function = []
                inside_function = False

    # 处理文件末尾的残余函数
    if current_function:
        functions.append(''.join(class_context + current_function))

    return functions

def save_functions_to_files(functions, result_dir):
    """
    将函数列表保存为单独的txt文件
    :param functions: 函数内容列表
    :param result_dir: 保存目录路径
    """
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
    
    for idx, func in enumerate(functions):
        file_name = os.path.join(result_dir, f'function_{idx + 1}.txt')
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(func)

def process_php_file(file_path):
    """
    处理单个PHP文件，提取函数并保存
    :param file_path: PHP文件路径
    """
    result_dir = f"{os.path.splitext(file_path)[0]}_result"
    
    print(f"Processing {file_path}...")
    try:
        functions = extract_php_functions_with_context(file_path)
        save_functions_to_files(functions, result_dir)
        print(f"Extracted {len(functions)} functions from {file_path}.")
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    return functions

def process_php_files_in_directory(directory):
    """
    扫描指定目录下的所有PHP文件并处理
    :param directory: 目录路径
    """
    functions=[]
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                functions+=process_php_file(file_path)
    return functions
