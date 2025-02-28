## These are decorators you can call from anywhere! Yay!

def rawProfileTime(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        return result
    return wrapper