from structure import Analyzer, Report
import logging

class ZipAnalyzer(Analyzer):
    compatible_mime_types = ['application/zip']
    description = "ZIP-File analyser"
    passwords = ["infected","Infected","iNFECTED","INFECTED"]

    def _test_pw(self):
        for password in self.passwords:
            self.zipobj.setpassword(bytes(password,'utf-8'))
            try:
                test = self.zipobj.testzip()
                self.reports['password'] = Report(password)
                return True
            except RuntimeError as e:
                if e.args[0].startswith('Bad password for file'):
                    return False
                raise e

    def _isencrypted(self):
        for file in self.zipobj.filelist:
            if file.flag_bits & 0x1 :
                return True
        return False

    def analysis(self):
        super().analysis()
        import zipfile, io
        file_like_object = io.BytesIO(self.struct.rawdata)
        self.zipobj = zipfile.ZipFile(file_like_object)
        self.info = f'{len(self.zipobj.filelist)} compressed file(s)'
        filelist = [f'{f.filename} {("<encrypted>" if f.flag_bits & 0x1 else "")} [{f.file_size}]' for f in self.zipobj.filelist]
        self.reports['summary'] = Report("\n".join(filelist))
        if self._isencrypted():
            self.reports['encrypted'] = Report("ZIP File is Password protected")
            self._test_pw()

        for idx, zipped_file in enumerate(self.zipobj.namelist()):
            self.childitems.append(self.generate_struct(filename=zipped_file, data=self.zipobj.read(zipped_file), index=idx))
