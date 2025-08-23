import json
import textwrap

class ReportManager:
    def __init__(self, structure, verbosity=0):
        self.structure = structure
        self.verbosity = verbosity
        self.report_tree = self._build_report_tree(self.structure)

    def _build_report_tree(self, structure_item):
        report_node = {
            "info": {
                "index": structure_item.index,
                "mime_type": structure_item.mime_type,
                "size": structure_item.size,
                "filename": structure_item.filename if structure_item.has_filename else None,
                "md5": structure_item.md5,
                "analyzer_info": structure_item.analyzer.info,
            },
            "reports": [report.to_dict() for report in structure_item.analyzer.summary if report.verbosity <= self.verbosity],
            "children": [self._build_report_tree(child) for child in structure_item.get_children()]
        }
        return report_node

    def render(self, format='text'):
        if format == 'text':
            return self.render_text(self.report_tree)
        elif format == 'markdown':
            return self.render_markdown(self.report_tree)
        elif format == 'html':
            return self.render_html(self.report_tree)
        elif format == 'json':
            return json.dumps(self.report_tree, indent=4)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def render_text(self, node, level=0):
        return "".join(self._render_text_root(self.report_tree))

    def _render_text_root(self, node):
        yield f"{node['info']['index']} >> {node['info']['mime_type']} {node['info']['size']}\n"
        yield f"info     : {node['info']['analyzer_info']}\n"
        if node['info']['filename']:
            yield f"filename : {node['info']['filename']}\n"
        yield f"md5      : {node['info']['md5']}\n"

        for report in node['reports']:
            label = report['label'] or ''
            if report['content_type'] == 'image/png':
                yield f"{label} : [Image: {report['text'] or 'preview in HTML report'}]\n"
            else:
                text = str(report['text'] or '')
                lines = textwrap.wrap(text, width=100, subsequent_indent='  ')
                if not lines:
                    yield f"{label} : \n"
                else:
                    yield f"{label} : {lines[0]}\n"
                    for line in lines[1:]:
                        yield f"  {line}\n"

        num_children = len(node['children'])
        for i, child in enumerate(node['children']):
            is_last = (i == num_children - 1)
            yield from self._render_text_child(child, prefix="", is_last=is_last)

    def _render_text_child(self, node, prefix, is_last):
        connector = "└── " if is_last else "├── "
        yield f"{prefix}{connector}{node['info']['index']} >> {node['info']['mime_type']} {node['info']['size']}\n"

        content_prefix = prefix + ("    " if is_last else "│   ")

        yield f"{content_prefix}info     : {node['info']['analyzer_info']}\n"
        if node['info']['filename']:
            yield f"{content_prefix}filename : {node['info']['filename']}\n"
        yield f"{content_prefix}md5      : {node['info']['md5']}\n"

        for report in node['reports']:
            label = report['label'] or ''
            if report['content_type'] == 'image/png':
                yield f"{content_prefix}{label} : [Image: {report['text'] or 'preview in HTML report'}]\n"
            else:
                text = str(report['text'] or '')
                lines = textwrap.wrap(text, width=100, subsequent_indent='  ')
                if not lines:
                    yield f"{content_prefix}{label} : \n"
                else:
                    yield f"{content_prefix}{label} : {lines[0]}\n"
                    for line in lines[1:]:
                        yield f"{content_prefix}  {line}\n"

        num_children = len(node['children'])
        for i, child in enumerate(node['children']):
            child_is_last = (i == num_children - 1)
            yield from self._render_text_child(child, prefix=content_prefix, is_last=child_is_last)

    def render_markdown(self, node, level=0):
        indent = "  " * level
        report_str = f"{indent}* **{node['info']['mime_type']}** ({node['info']['size']} bytes)\n"
        report_str += f"{indent}  * **Info**: {node['info']['analyzer_info']}\n"
        if node['info']['filename']:
            report_str += f"{indent}  * **Filename**: {node['info']['filename']}\n"
        report_str += f"{indent}  * **MD5**: {node['info']['md5']}\n"
        for report in node['reports']:
            if report['content_type'] == 'image/png':
                report_str += f"{indent}  * **{report['label']}**: [Image: {report['text'] or 'preview in HTML report'}]\n"
            else:
                report_str += f"{indent}  * **{report['label']}**: {report['text']}\n"
        for child in node['children']:
            report_str += self.render_markdown(child, level + 1)
        return report_str

    def render_html(self, node, level=0):
        report_str = "<ul>\n"
        report_str += f"<li><b>{node['info']['mime_type']}</b> ({node['info']['size']} bytes)</li>\n"
        report_str += "<ul>\n"
        report_str += f"<li><b>Info</b>: {node['info']['analyzer_info']}</li>\n"
        if node['info']['filename']:
            report_str += f"<li><b>Filename</b>: {node['info']['filename']}</li>\n"
        report_str += f"<li><b>MD5</b>: {node['info']['md5']}</li>\n"
        for report in node['reports']:
            if report['content_type'] == 'image/png' and report['data']:
                report_str += f"<li><b>{report['label']}</b>: <img src=\"data:image/png;base64,{report['data']}\" alt=\"{report['text']}\"></li>\n"
            else:
                report_str += f"<li><b>{report['label']}</b>: {report['text']}</li>\n"
        for child in node['children']:
            report_str += self.render_html(child, level + 1)
        report_str += "</ul>\n"
        report_str += "</ul>\n"
        return report_str
