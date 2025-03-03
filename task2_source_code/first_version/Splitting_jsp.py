import os

def split_jsp_files(directory, max_chars=14000):
    functions=[]
    """
    Splits .jsp files in the specified directory into smaller files of up to `max_chars` characters.
    
    Args:
        directory (str): The path of the directory containing .jsp files.
        max_chars (int): Maximum number of characters in each split file.
    """
    # Ensure the provided directory exists
    if not os.path.isdir(directory):
        print(f"Error: The directory '{directory}' does not exist.")
        return
    
    # Get all .jsp files in the directory
    jsp_files = [f for f in os.listdir(directory) if f.endswith('.jsp')]
    if not jsp_files:
        print(f"No .jsp files found in the directory: {directory}")
        return

    # Process each .jsp file
    for jsp_file in jsp_files:
        filepath = os.path.join(directory, jsp_file)
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Split content into chunks
        chunks = [content[i:i+max_chars] for i in range(0, len(content), max_chars)]
        
        # Create a result directory for the split files
        result_dir = os.path.join(directory, f"{jsp_file}_result")
        os.makedirs(result_dir, exist_ok=True)
        functions+=chunks
    return functions