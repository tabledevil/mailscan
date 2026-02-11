import logging
from .base import BaseAnalyzer, Report, AnalysisModuleException

# To use a new dependency, import it here.
# If the dependency is optional, wrap the import in a try...except block.
# For example:
# try:
#     import new_dependency
# except ImportError:
#     new_dependency = None

class TemplateAnalyzer(BaseAnalyzer):
    """
    This is a template for a new analyzer.
    Copy this file and rename it to something like 'MyNewAnalyzer.py'.
    Then, change the class name from 'TemplateAnalyzer' to 'MyNewAnalyzer'.
    """

    # A list of MIME types that this analyzer can handle.
    compatible_mime_types = ['application/x-my-new-format']

    # A short description of the analyzer.
    description = "My New Analyzer"

    # A list of required pip packages.
    # The tool's --check command will verify that these are installed.
    pip_dependencies = ['new_dependency']

    # A list of required system commands.
    # The tool's --check command will verify that these are installed.
    system_dependencies = ['new_command']

    def analysis(self):
        """
        This is the main analysis method.
        It is called by the framework after the analyzer is initialized.
        """
        # Call the parent analysis method first.
        super().analysis()

        # Check if optional dependencies are installed.
        # if not new_dependency:
        #     logging.warning("new_dependency is not installed, cannot perform some analysis.")
        #     return

        # The raw data of the file is available in self.struct.rawdata.
        # The filename is in self.struct.filename.

        # You can add reports to the analyzer.
        # A report is a key-value pair that will be displayed in the output.
        self.reports['my_report'] = Report("This is my report.")

        # You can also add child items.
        # A child item is a new piece of data that will be analyzed by the framework.
        # For example, if you are analyzing an archive, you can add the extracted
        # files as child items.
        # new_data = b"This is a new piece of data."
        # self.childitems.append(self.generate_struct(data=new_data, filename="new_file.txt", mime_type="text/plain"))

        # If something goes wrong, you can raise an AnalysisModuleException.
        # raise AnalysisModuleException("Something went wrong.")

        # The info property is a short string that summarizes the analysis.
        self.info = "This is a summary of the analysis."

        # The analysis method can be broken down into smaller methods using the
        # self.modules dictionary. This is useful for organizing your code.
        # self.modules['my_module'] = self.my_module_method
        # self.run_modules()

    # def my_module_method(self):
    #     """
    #     This is an example of a module method.
    #     """
    #     pass
