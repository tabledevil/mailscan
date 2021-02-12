from structure import Analyzer, Report
import logging

class ZipAnalyzer(Analyzer):
    compatible_mime_types = ['application/zip']
    description = "ZIP-File analyser"

    def analysis(self):
        super().analysis()
        import zipfile, io
        file_like_object = io.BytesIO(self.struct.rawdata)
        self.zipobj = zipfile.ZipFile(file_like_object)
        self.info = f'{len(self.zipobj.filelist)} compressed file(s)'
        filelist = [f'{f.filename} [{f.file_size}]' for f in self.zipobj.filelist]
        self.reports['summary'] = Report('\n'.join(filelist))

    def get_childitems(self) -> list():
        return [self.generate_struct(filename=name, data=self.zipobj.read(name), level=self.struct.level + 1, index=index) for
                index, name in enumerate(self.zipobj.namelist())]
