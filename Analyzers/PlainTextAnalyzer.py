from structure import Analyzer, Report
import logging

import textwrap

class PlainTextAnalyzer(Analyzer):
    compatible_mime_types = ['text/plain']
    description = 'Plain Textfile Analyser'
    LANGUAGE_DB = 'lid.176.ftz'
    LANGUAGE_DB_URL = 'https://dl.fbaipublicfiles.com/fasttext/supervised-models/lid.176.ftz'

    # def detect_language_fasttext(self):
    #     import fasttext
    #     if not os.path.isfile(self.LANGUAGE_DB):
    #         import requests
    #         logging.debug('Language File not Found. Download Starting...')
    #         r = requests.get(self.LANGUAGE_DB_URL)
    #         with open(self.LANGUAGE_DB, 'wb') as output_file:
    #             output_file.write(r.content)
    #     model = fasttext.load_model(self.LANGUAGE_DB)
    #     predictions, _ = model.predict(self.text.splitlines())
    #     predictions = [p[0] for p in predictions]
    #     return max(set(predictions), key=predictions.count).replace('__label__', '')

    def detect_language_langdetect(self):
        from langdetect import detect
        return detect(self.text)

    def detect_lang(self):
        resp = ""
        try:
            resp = self.detect_language_fasttext()
        except:
            pass
        if resp == "":
            try:
                resp = self.detect_language_langdetect()
            except:
                pass
        return resp

    def __decode(self, string):
        if isinstance(string, str):
            return string
        if isinstance(string, bytes):
            encodings = ['utf-8-sig', 'utf-16', 'iso-8859-15']
            encodings = self.__guess_encoding(string) + encodings
            for encoding in encodings:
                try:
                    return string.decode(encoding, errors='ignore')
                except UnicodeDecodeError:
                    pass

    def __guess_encoding(self, string):
        try:
            import chardet
            detection = chardet.detect(string)
            if "encoding" in detection and detection['encoding'] is not None and len(detection["encoding"]) > 2:
                return [detection["encoding"]]
        except ImportError:
            logging.warning('Missing module chardet')
        return []

    def decode(self):
        self.text = self.__decode(self.struct.rawdata)

    def analysis(self):
        self.text = "Could not decode"
        self.lang = ""
        self.modules['encoding'] = self.decode
        self.modules['language'] = self.detect_lang
        super().analysis()

        # self.lang = self.detect_lang()
        self.info = f"language:{self.lang} {len(self.text)}"
        self.reports['summary'] = Report(self.text, short=textwrap.shorten(self.text, width=100))