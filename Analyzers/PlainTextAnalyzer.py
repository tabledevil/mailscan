from structure import Analyzer, Report
import logging

import os
import textwrap

class PlainTextAnalyzer(Analyzer):
    compatible_mime_types = ['text/plain']
    description = 'Plain Textfile Analyser'
    LANGUAGE_DB = 'lid.176.ftz'
    LANGUAGE_DB_URL = 'https://dl.fbaipublicfiles.com/fasttext/supervised-models/lid.176.ftz'

    def __detect_language_cld3(self):
        import cld3
        resp = cld3.get_language(self.text)
        self.reports['lang_cld3']=Report(f'{resp.language}@{resp.probability}')
        if resp.is_reliable:
            return resp.language
        return ""
        #LanguagePrediction(language='zh', probability=0.999969482421875, is_reliable=True, proportion=1.0)

    def __detect_language_fasttext(self):
        import fasttext
        if not os.path.isfile(self.LANGUAGE_DB):
            import requests
            logging.warning('Language File not Found. Download Starting...')
            r = requests.get(self.LANGUAGE_DB_URL)
            with open(self.LANGUAGE_DB, 'wb') as output_file:
                output_file.write(r.content)
        model = fasttext.load_model(self.LANGUAGE_DB)
        predictions, _ = model.predict(self.text.splitlines())
        predictions = [p[0] for p in predictions]
        language = max(set(predictions), key=predictions.count).replace('__label__', '')
        self.reports['lang_fasttext']=Report(f'{language}')
        return language
    
    def __detect_language_langdetect(self):
        from langdetect import detect
        language = detect(self.text)
        self.reports['lang_langdetect']=Report(f'{language}')
        return language

    def detect_lang(self):
        resp = None
        detectors = [self.__detect_language_cld3,self.__detect_language_fasttext,self.__detect_language_langdetect]
        for detector in detectors:
            try:
                resp = detector()
            except:
                pass
            if resp is not None:
                break
        if resp is None:
            logging.warning('No language Detection module installed. [langdetec,fasttext,pycld3]')
        self.lang=resp

        self.reports['language'] = Report(resp)

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
                self.reports['encoding']=Report(detection["encoding"])
                return [detection["encoding"]]
        except ImportError:
            logging.warning('Missing module chardet')
        return []

    def decode(self):
        self.text = self.__decode(self.struct.rawdata)

    def analysis(self):
        self.text = ""
        self.lang = ""
        self.modules['encoding'] = self.decode
        self.modules['language'] = self.detect_lang
        super().analysis()

        # self.lang = self.detect_lang()
        self.info = f"language:{self.lang}"
        self.reports['summary'] = Report(self.text, short=textwrap.shorten(self.text, width=100))