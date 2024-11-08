import pprint
BR_VERSION = "00.00.01-alpha"

test = bytes(BR_VERSION.encode('utf-8'))

print(pprint.pformat(test.hex(" ", 1)))
print(len(test))

