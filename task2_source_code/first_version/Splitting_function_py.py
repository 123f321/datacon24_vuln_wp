import os
import ast

def extract_functions_from_file(file_path):
    """
    Extract all functions from a single Python file and return a dictionary.
    Keys are function names, and values are the full code of the functions.
    """
    print(f"[DEBUG] Attempting to read file: {file_path}")
    with open(file_path, 'r', encoding='utf-8') as file:
        file_content = file.read()

    try:
        # Parse Python code using the AST module
        tree = ast.parse(file_content)
        print(f"[DEBUG] Successfully parsed file: {file_path}")
    except SyntaxError as e:
        print(f"[ERROR] Syntax error in file: {file_path} - {e}")
        return {}

    functions = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):  # Find function definitions
            func_name = node.name
            func_code = ast.get_source_segment(file_content, node)
            functions[func_name] = func_code
            print(f"[DEBUG] Extracted function: {func_name}")

    print(f"[INFO] Total functions extracted from {file_path}: {len(functions)}")
    return functions


def save_functions_to_files(functions, output_dir):
    """
    Save extracted functions as individual txt files.
    """
    print(f"[DEBUG] Preparing to save functions to directory: {output_dir}")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"[DEBUG] Created output directory: {output_dir}")

    for idx, (func_name, func_code) in enumerate(functions.items(), start=1):
        # Ensure unique filenames
        sanitized_name = func_name.replace('<', '').replace('>', '').replace(':', '_')
        output_file = os.path.join(output_dir, f"{idx}_{sanitized_name}.txt")
        try:
            with open(output_file, 'w', encoding='utf-8') as file:
                file.write(func_code)
            print(f"[INFO] Saved function: {func_name} to {output_file}")
        except Exception as e:
            print(f"[ERROR] Failed to save function: {func_name} - {e}")


def process_python(input_dir):
    """
    Traverse all Python files in the directory and extract functions.
    """
    print(f"[DEBUG] Starting directory traversal: {input_dir}")
    if not os.path.isdir(input_dir):
        print(f"[ERROR] Invalid directory: {input_dir}")
        return
    functions = []
    for root, _, files in os.walk(input_dir):
        for file_name in files:
            if file_name.endswith('.py'):
                file_path = os.path.join(root, file_name)
                print(f"[INFO] Processing file: {file_path}")

                # Extract functions
                functions += extract_functions_from_file(file_path)
    return functions


