import memory_profiler

def createThreadedTask(func: function):
    newTask = Task(func)

memory_profiler.profile()

class Task:

    def __init__(self, func):
        pass