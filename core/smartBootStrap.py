from rich.console import Console
from rich.spinner import Spinner
import time

import os

console = Console()


def find_packages(directory):
    packages = []
    with console.status("Scanning modules...", spinner="dots") as status:
        for root, dirs, files in os.walk(directory):
            if 'venv' in dirs:
                dirs.remove('venv')

            if '__init__.py' in files:
                # Remove the __init__.py from the path and append to the list
                package_path = os.path.relpath(root, directory)
                packages.append(package_path.replace(os.sep, '.'))
            
            status.update(status=f'Scanning modules... ({root})')
            time.sleep(0.15)
        return packages

def bootStrap():
    current_directory = os.getcwd()
    packages = find_packages(current_directory)
    console.print(packages)
