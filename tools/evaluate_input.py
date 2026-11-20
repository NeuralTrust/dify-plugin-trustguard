# Import the module (not the class) so the Dify class loader finds exactly one Tool subclass here.
import tools.base as base


class EvaluateInputTool(base.EvaluateTool):
    direction = "input"
