import hashlib

class H(dict):
    __slots__ = []
    def __init__(self,data:bytes): self['data']=data
    def __getattr__(self, key):
        if key in self:
            return self[key]
        if key in hashlib.algorithms_available:
            hasher = hashlib.new(key)
            hasher.update(self.data)
            self[key] = hasher.hexdigest()
            return self[key]
        else:
            raise AttributeError()
    def __setattr__(self, name, value): self[name] = value

a=H("test".encode())
a.test=2
print(a.data)
print(a.sha256)
print(a.test)