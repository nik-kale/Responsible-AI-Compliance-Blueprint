import pytest
import yaml
from pathlib import Path
from raicb.checks import code_quality
from raicb.config.schema import ProjectConfig, Status, Severity

def load_test_config(config_file):
    return ProjectConfig(**yaml.safe_load(config_file.read_text()))

def test_cyclomatic_complexity_high(tmp_path, sample_config):
    # Create a complex function
    code = "def complex_func():\n"
    for i in range(12):
        code += f"    if True: pass\n"

    (tmp_path / "complex.py").write_text(code)

    findings = code_quality._check_cyclomatic_complexity(tmp_path)

    # Should find 1 high complexity function
    warning = next((f for f in findings if f.status == Status.WARNING), None)
    assert warning is not None
    assert "High Cyclomatic Complexity" in warning.title
    assert "complex_func" in warning.details

def test_cyclomatic_complexity_ok(tmp_path):
    (tmp_path / "simple.py").write_text("def simple(): pass")
    findings = code_quality._check_cyclomatic_complexity(tmp_path)
    assert findings[0].status == Status.PASS

def test_function_length(tmp_path):
    # Create long function
    code = "def long_func():\n"
    code += "\n".join(["    pass" for _ in range(60)])

    (tmp_path / "long.py").write_text(code)

    findings = code_quality._check_function_length(tmp_path)
    warning = next((f for f in findings if f.status == Status.WARNING), None)
    assert warning is not None
    assert "Long Functions Detected" in warning.title

def test_magic_numbers(tmp_path):
    code = "x = 42\ny = 12345"
    (tmp_path / "magic.py").write_text(code)

    findings = code_quality._check_magic_numbers(tmp_path)
    # 42 might be ignored? The check ignores < 20 findings?
    # Let's check logic: if len(magic_numbers) > 20: ...
    # So I need > 20 magic numbers to trigger warning.

    code = "\n".join([f"x{i} = {i*100}" for i in range(25)])
    (tmp_path / "magic.py").write_text(code)

    findings = code_quality._check_magic_numbers(tmp_path)
    warning = next((f for f in findings if f.status == Status.WARNING), None)
    assert warning is not None
    assert "Magic Numbers Detected" in warning.title

