import os


def extract_java_functions_with_stack(file_path):
    """
    Extract all functions from a Java file using a stack-based approach to ensure complete function bodies.
    :param file_path: Path to the Java file
    :return: A list of all function code blocks
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    functions = []
    stack = []
    current_function = []
    inside_function = False

    for line in lines:
        stripped_line = line.strip()

        # Check for potential function signature
        if not inside_function and ("{" in stripped_line or "(" in stripped_line) and ")" in stripped_line:
            # Basic heuristic for identifying function signatures
            if any(keyword in stripped_line for keyword in ["public", "private", "protected", "void", "int", "String"]):
                inside_function = True

        if inside_function:
            current_function.append(line)

            # Track opening and closing braces using a stack
            for char in stripped_line:
                if char == "{":
                    stack.append("{")
                elif char == "}":
                    if stack:
                        stack.pop()

            # If the stack is empty, the function is complete
            if inside_function and not stack:
                functions.append("".join(current_function))
                current_function = []
                inside_function = False

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


def process_java_files(input_dir):
    """
    Process all Java files in the specified directory.
    :param input_dir: Path to the input directory
    """
    functions=[]
    for root, _, files in os.walk(input_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                file_name = os.path.splitext(file)[0]
                output_dir = input_dir+f"\{file_name}_result"

                print(f"Processing file: {file_path}")
                functions += extract_java_functions_with_stack(file_path)
    return functions


