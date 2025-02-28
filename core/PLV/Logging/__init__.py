import os

if not os.path.isdir("temp"):
    os.mkdir("temp")
    print("logging init has created a temp dir for runtime.")
from core.PLV.Logging import classic, extended, profiler
