from structure import Analyzer, Report
import xml.etree.ElementTree as ET

class OfficeRelationshipAnalyzer(Analyzer):
    """
    Analyzes Office Relationship (.rels) files for malicious external links.
    """
    compatible_mime_types = ['application/vnd.openxmlformats-package.relationships+xml', 'application/xml']
    description = "Office Relationship File (.rels) Analyzer"

    def analysis(self):
        # Only run on .rels files, even if mime is generic application/xml
        if self.struct.filename and not self.struct.filename.endswith('.rels'):
            return

        super().analysis()

        ns = {'r': 'http://schemas.openxmlformats.org/package/2006/relationships'}

        try:
            # The rawdata is bytes, ElementTree needs a string.
            xml_content = self.struct.rawdata.decode('utf-8')
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            self.reports['parse_error'] = Report(f"XML Parse Error: {e}", rank=1)
            return
        except UnicodeDecodeError as e:
            self.reports['decode_error'] = Report(f"Unicode Decode Error: {e}", rank=1)
            return

        found_external = False
        for idx, rel in enumerate(root.findall('r:Relationship', ns)):
            if rel.get('TargetMode') == 'External':
                found_external = True
                target = rel.get('Target', 'N/A')
                rel_type = rel.get('Type', 'N/A')
                rel_type_suffix = rel_type.split('/')[-1]

                report_key_base = f"external_link_{idx}"

                if 'attachedTemplate' in rel_type:
                    report = Report(f"CRITICAL: Remote Template Injection detected. Target: {target}", rank=2)
                    self.reports[f"{report_key_base}_remote_template"] = report
                elif target.startswith('file://'):
                    report = Report(f"CRITICAL: Potential NTLM hash leak via file:// link. Target: {target}", rank=2)
                    self.reports[f"{report_key_base}_ntlm_leak"] = report
                elif 'altChunk' in rel_type:
                    report = Report(f"WARNING: External altChunk found, can import external content. Target: {target}", rank=1)
                    self.reports[f"{report_key_base}_altchunk"] = report
                else:
                    report = Report(f"WARNING: External link of type '{rel_type_suffix}' found. Target: {target}", rank=1)
                    self.reports[f"{report_key_base}_generic"] = report

        if found_external:
            self.info = "Found one or more external relationships."
        else:
            self.info = "No external relationships found."
