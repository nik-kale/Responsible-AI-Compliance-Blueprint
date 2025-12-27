# Architecture

## Overview

RAICB is built with a modular architecture centered around the `Evaluator`.

```mermaid
graph TD
    CLI --> Evaluator
    Evaluator --> Loader
    Evaluator --> Checks
    Evaluator --> Report
    Checks --> CoreChecks
    Checks --> Plugins
```

## Components

- **CLI**: Entry point (Typer)
- **Evaluator**: Orchestrates execution
- **Loader**: Loads configuration
- **Checks**: Compliance logic
- **Report**: Generates outputs

