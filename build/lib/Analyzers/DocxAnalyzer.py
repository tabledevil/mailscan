from structure import Analyzer, Report
import zipfile
import io
import os

class DocxAnalyzer(Analyzer):
    """
    DOCX Analyzer.
    This analyzer acts as a conductor for .docx files. It performs structural
    analysis on the docx container and creates child objects for the internal
    files, which are then analyzed by other specialized analyzers.
    """
    compatible_mime_types = ['application/vnd.openxmlformats-officedocument.wordprocessingml.document']
    description = "Microsoft Word Document (DOCX) Analyzer"

    def analysis(self):
        super().analysis()

        # Open the docx file (which is a zip archive)
        try:
            file_like_object = io.BytesIO(self.struct.rawdata)
            self.zipobj = zipfile.ZipFile(file_like_object)
            self.filelist = self.zipobj.namelist()
            self.info = f'{len(self.filelist)} files in archive'
        except zipfile.BadZipFile:
            self.reports['error'] = Report("Invalid DOCX file (not a valid zip archive).")
            return

        # --- Structural Analysis ---
        # These are checks that look at the file paths within the archive,
        # not the content of any single file.

        # Check for ActiveX directory structure
        activex_files = [f for f in self.filelist if f.startswith('word/activeX/')]
        if activex_files:
            self.reports['activeX'] = Report("ActiveX control files found within the document.", rank=2)

        # Check for OLE embedded objects
        ole_files = [os.path.basename(f) for f in self.filelist if f.startswith('word/embeddings/')]
        if ole_files:
            self.reports['ole_objects'] = Report(f"Embedded OLE objects found: {', '.join(ole_files)}", rank=1)

        # Check for embedded fonts
        font_files = [os.path.basename(f) for f in self.filelist if f.startswith('word/fonts/')]
        if font_files:
            self.reports['embedded_fonts'] = Report(f"Embedded fonts found: {', '.join(font_files)}", rank=0)

        # --- Child Generation ---
        # Create child structures for each file inside the docx archive.
        # The framework will then dispatch these to other analyzers.
        for idx, zipped_file_path in enumerate(self.filelist):
            # Don't create children for directory entries
            if not zipped_file_path.endswith('/'):
                try:
                    child_data = self.zipobj.read(zipped_file_path)
                    child_struct = self.generate_struct(filename=zipped_file_path, data=child_data, index=idx)

                    # Manually set the parent for context-aware child analysis
                    child_struct.parent = self.struct

                    self.childitems.append(child_struct)
                except Exception as e:
                    self.reports[f'child_error_{idx}'] = Report(f"Error reading child file {zipped_file_path}: {e}", rank=2)
