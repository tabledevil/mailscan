__all__ = ['flags']

class Flags(object):
    def __init__(self, *items):
        for key,val in zip(items[:-1], items[1:]):
            setattr(self,key,val)

flags = Flags('debug', False,
              'max_analysis_depth', 10,
              'max_file_size', 1024*1024*1024,
              'max_compression_ratio', 100)

