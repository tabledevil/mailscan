from structure import Analyzer, Report
import logging

class ZipAnalyzer(Analyzer):
    compatible_mime_types = ['application/x-7z-compressed']
    description = "7Z-File analyser"
    passwords = ["infected","Infected","iNFECTED","INFECTED"]
    passwords += ["ibfected","ibnfected","ifected","ifnected","igfected","ignfected","ihfected","ihnfected","iinfected","ijfected","ijnfected","imfected","imnfected","inbected","inbfected","incected","incfected","indected","indfected","inected","ineected","inefcted","inefected","infceted","infcted","infdcted","infdected","infeccted","infeced","infecetd","infecfed","infecfted","infecged","infecgted","infeched","infechted","infecred","infecrted","infectde","infectded","infecte","infectec","infectecd","infectedd","infectee","infecteed","infectef","infectefd","infecter","infecterd","infectes","infectesd","infectev","infectevd","infectew","infectewd","infectex","infectexd","infectfed","infectred","infectsed","infectted","infectwed","infecyed","infecyted","infedcted","infedted","infeected","infefcted","infefted","infescted","infested","infetced","infeted","infevcted","infevted","infexcted","infexted","inffcted","inffected","infrcted","infrected","infscted","infsected","infwcted","infwected","ingected","ingfected","innfected","inrected","inrfected","intected","intfected","invected","invfected","jinfected","jnfected","kinfected","knfected","linfected","lnfected","nfected","nifected","oinfected","onfected","uinfected","unfected"]

    def analysis(self):
        super().analysis()
        import py7zr, tempfile, lzma, os

        #Write data to tempfile 
        tmpfile = tempfile.NamedTemporaryFile(mode='w+b',delete=False)
        tmpfile.write(self.struct.rawdata)
        tmpfile.close()

        try:
            self.zipobj = py7zr.SevenZipFile(tmpfile.name)
        except py7zr.exceptions.Bad7zFile:
            logging.warning("Not a 7z-File")
        zipped_files = None
        if self.zipobj.password_protected:
            for password in self.passwords:
                try:
                    self.zipobj = py7zr.SevenZipFile(tmpfile.name,password=password)
                    zipped_files = self.zipobj.readall()
                    if len(zipped_files) > 0:
                        break
                except lzma.LZMAError:
                    logging.debug(f"Wrong password : {password}")
            if zipped_files is None:
                logging.error("Couldn't guess password")
        else:
            zipped_files = self.zipobj.readall()
        if zipped_files and len(zipped_files)>0:
            for idx, zipped_file in enumerate(zipped_files):
                print(f"{idx} : {zipped_file} : ")
                print(zipped_files[zipped_file])
                self.childitems.append(self.generate_struct(filename=zipped_file, data=zipped_files[zipped_file].read(), index=idx))

        #self.info = f'{len(self.zipobj.filelist)} compressed file(s)'
        filelist = [f'{f.filename} [{f.uncompressed}]' for f in self.zipobj.list()]
        self.reports['summary'] = Report('\n'.join(filelist))
        os.remove(tmpfile.name)

