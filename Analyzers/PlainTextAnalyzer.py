import logging
import os
import textwrap
import re
from structure import Analyzer, Report

try:
    import cld3
except ImportError:
    cld3 = None

try:
    import fasttext
except ImportError:
    fasttext = None

try:
    from langdetect import detect, lang_detect_exception
except ImportError:
    detect = None
    lang_detect_exception = None

try:
    import chardet
except ImportError:
    chardet = None

try:
    import requests
except ImportError:
    requests = None


class PlainTextAnalyzer(Analyzer):
    compatible_mime_types = ['text/plain']
    description = 'Plain Textfile Analyser'
    pip_dependencies = ['pycld3', 'fasttext', 'langdetect', 'chardet', 'requests']

    LANGUAGE_DB = 'lid.176.ftz'
    LANGUAGE_DB_URL = 'https://dl.fbaipublicfiles.com/fasttext/supervised-models/lid.176.ftz'
    _fasttext_model = None

    def __detect_language_cld3(self):
        if not cld3: return None
        resp = cld3.get_language(self.text)
        self.reports['lang_cld3']=Report(f'{resp.language}@{resp.probability}')
        return resp.language if resp.is_reliable else ""

    def __detect_language_fasttext(self):
        if not fasttext: return None
        if PlainTextAnalyzer._fasttext_model is None:
            if not os.path.isfile(self.LANGUAGE_DB):
                if not requests:
                    logging.warning("requests library not found, cannot download fasttext model.")
                    return None
                logging.warning('Language File not Found. Download Starting...')
                r = requests.get(self.LANGUAGE_DB_URL)
                with open(self.LANGUAGE_DB, 'wb') as output_file:
                    output_file.write(r.content)
            PlainTextAnalyzer._fasttext_model = fasttext.load_model(self.LANGUAGE_DB)
        model = PlainTextAnalyzer._fasttext_model
        # Suppressing fasttext warning about loading model from disk
        predictions, _ = model.predict(self.text.replace('\n', ' ').splitlines())
        predictions = [p[0] for p in predictions if p]
        if not predictions: return None
        language = max(set(predictions), key=predictions.count).replace('__label__', '')
        self.reports['lang_fasttext']=Report(f'{language}')
        return language
    
    def __detect_language_langdetect(self):
        if not detect: return None
        try:
            language = detect(self.text)
        except lang_detect_exception.LangDetectException as e:
            language = f"[{e}]"
        self.reports['lang_langdetect']=Report(f'{language}')
        return language

    def detect_lang(self):
        resp = None
        detectors = [self.__detect_language_cld3, self.__detect_language_fasttext, self.__detect_language_langdetect]
        for detector in detectors:
            try:
                resp = detector()
                if resp: break
            except Exception as e:
                logging.debug(f"Language detector {detector.__name__} failed: {e}")

        if resp is None:
            logging.warning('No language Detection module installed or working. [pycld3, fasttext, langdetect]')
        self.lang=resp
        self.reports['language'] = Report(resp)

    def __decode(self, string):
        if isinstance(string, str):
            return string
        if isinstance(string, bytes):
            encodings = ['utf-8-sig', 'utf-16', 'iso-8859-15']
            guessed_encodings = self.__guess_encoding(string)
            if guessed_encodings:
                encodings = guessed_encodings + encodings
            for encoding in encodings:
                try:
                    return string.decode(encoding, errors='ignore')
                except UnicodeDecodeError:
                    pass
        return ""

    def __guess_encoding(self, string):
        if not chardet:
            logging.warning('Missing module chardet')
            return []
        detection = chardet.detect(string)
        if "encoding" in detection and detection['encoding'] is not None:
            self.reports['encoding']=Report(detection["encoding"])
            return [detection["encoding"]]
        return []

    def scan4passwords(self):
        if len(self.text) > 0:
            _RE_FIND_PW = re.compile(r'''(pw|kennwort|pass(wor[dt])?)(?P<words>.*)''', re.IGNORECASE)
            match = _RE_FIND_PW.search(self.text)
            if match:
                words=[word for word in match.group('words').split() if len(word) > 3]
                if len(words) > 0 :
                    self.reports['possible_passwords'] = Report(",".join(words))

    def decode(self):
        self.text = self.__decode(self.struct.rawdata)

    def analysis(self):
        self.text = ""
        self.lang = ""
        self.modules['encoding'] = self.decode
        self.modules['language'] = self.detect_lang
        self.modules['passwords'] = self.scan4passwords
        super().analysis()
        self.info = f"language:{self.lang}"
        self.reports['summary'] = Report(self.text, short=textwrap.shorten(self.text, width=100))