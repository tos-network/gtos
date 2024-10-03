import sha3
import json

# Function to calculate the 4-byte selector
def calculate_4byte_selector(signature):
    keccak = sha3.keccak_256()
    keccak.update(signature.encode('utf-8'))
    return keccak.hexdigest()[:8]  # Extract the first 4 bytes in hexadecimal format

# Read data from the 4byte.json file
with open('4byte.json', 'r') as file:
    function_signatures = json.load(file)  # Assuming 4byte.json is in dictionary format

# Recalculate the 4-byte selectors and generate a new dictionary list
new_4byte_json = []
for wrong_selector, signature in function_signatures.items():
    correct_selector = calculate_4byte_selector(signature)
    new_4byte_json.append(f'"{correct_selector}": "{signature}"')  # Create a formatted string

# Save the result into the new new4byte.json file
with open('new4byte.json', 'w') as new_file:
    new_file.write("{\n")  # Open the JSON object
    new_file.write(",\n".join(new_4byte_json))  # Join all lines with commas
    new_file.write("\n}")  # Close the JSON object

# Output success message
print("Successfully recalculated the 4-byte selectors and saved the result to new4byte.json.")

