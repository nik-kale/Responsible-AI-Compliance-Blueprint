# Plugin Development Guide

RAICB supports custom check plugins.

## Implementing a Plugin

Create a class that follows the `ComplianceCheckPlugin` protocol.

```python
from typing import List
from pathlib import Path
from raicb.core.plugin import ComplianceCheckPlugin
from raicb.config.schema import ProjectConfig, Finding

class MyCustomPlugin(ComplianceCheckPlugin):
    name = "My Custom Check"
    version = "1.0.0"

    def run_checks(self, config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
        return []
```

