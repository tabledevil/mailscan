import logging

analyzers_list = [
    "EmailAnalyzer",
    "PlainTextAnalyzer",
    "ZipAnalyzer",
    "SevenZipAnalyzer",
    "HTMLAnalyzer",
    "PDFAnalyzer",
    "MsgAnalyzer",
    "MboxAnalyzer",
    "DocxAnalyzer",
    "OfficeRelationshipAnalyzer",
    "OfficeXMLAnalyzer",
    "VBAProjectAnalyzer",
]

for module_name in analyzers_list:
    try:
        # Import the module
        module = __import__(f"Analyzers.{module_name}", fromlist=["*"])

        # update globals with the module's attributes (simulating 'from module import *')
        # We only want to export what the module exports (classes, mostly)
        # Usually Analyzer subclasses.
        for name in dir(module):
            if not name.startswith("_"):
                globals()[name] = getattr(module, name)

    except ImportError as e:
        logging.warning(f"Failed to import Analyzer {module_name}: {e}")
    except Exception as e:
        logging.warning(f"Unexpected error importing Analyzer {module_name}: {e}")
