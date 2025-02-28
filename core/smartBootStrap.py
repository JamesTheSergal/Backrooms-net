from rich.console import Console
from rich.spinner import Spinner

import os

console = Console()


def find_packages(directory):
    packages = []
    spinner = Spinner("dots", text="Scanning modules...")
    console.print(spinner)
    for root, dirs, files in os.walk(directory):
        if 'venv' in dirs:
            dirs.remove('venv')
            
        if '__init__.py' in files:
            # Remove the __init__.py from the path and append to the list
            package_path = os.path.relpath(root, directory)
            spinner.update(text=f'Scanning modules... ({package_path})')
            packages.append(package_path.replace(os.sep, '.'))
    return packages

def bootStrap():
    current_directory = os.getcwd()
    packages = find_packages(current_directory)
    console.print(packages)
