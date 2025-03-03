import os
import re


def extract_c_functions_with_stack(file_path):
    """
    Extract all functions from a C/C++ file using a stack-based approach to ensure complete function bodies.
    :param file_path: Path to the C/C++ file
    :return: A list of all function code blocks
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    functions = []
    stack = []
    current_function = []
    inside_function = False
    signature_detected = False

    for line in lines:
        stripped_line = line.strip()

        # Detect potential function signature
        if not inside_function and re.match(r"^[\w\s\*\&]+[\w\*]+\s*\([^)]*\)\s*\{?$", stripped_line):
            signature_detected = True
            inside_function = True
            current_function.append(line)

        elif inside_function:
            current_function.append(line)

            # Track opening and closing braces using a stack
            for char in stripped_line:
                if char == "{":
                    stack.append("{")
                elif char == "}":
                    if stack:
                        stack.pop()

            # If the stack is empty, the function is complete
            if not stack:
                functions.append("".join(current_function))
                current_function = []
                inside_function = False
                signature_detected = False

        elif signature_detected:
            # Handle multi-line function signature
            current_function.append(line)
            if "{" in stripped_line:
                inside_function = True
                for char in stripped_line:
                    if char == "{":
                        stack.append("{")
                    elif char == "}":
                        if stack:
                            stack.pop()

    return functions


def save_functions_to_files(functions, file_name, output_dir):
    """
    Save extracted functions to individual txt files.
    :param functions: List of extracted functions
    :param file_name: Original file name (without path)
    :param output_dir: Path to the output directory
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for i, function in enumerate(functions):
        output_file = os.path.join(output_dir, f"{file_name}_function_{i + 1}.txt")
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(function)


def process_c_files(input_dir):
    """
    Process all C files in the specified directory.
    :param input_dir: Path to the input directory
    """
    functions=[]
    for root, _, files in os.walk(input_dir):
        for file in files:
            if file.endswith('.c') or file.endswith('.cpp') or file.endswith('.h') or file.endswith('.cc'):
                file_path = os.path.join(root, file)
                file_name = os.path.splitext(file)[0]
                output_dir = input_dir+f"\{file_name}_result"

                print(f"Processing file: {file_path}")
                functions += extract_c_functions_with_stack(file_path)
                if functions:
                    #save_functions_to_files(functions, file_name, output_dir)
                    print(f"Processing complete. Functions saved in: {output_dir}")
                else:
                    print(f"No functions found in file: {file_path}")

    return functions