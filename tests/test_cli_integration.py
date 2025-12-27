from raicb.cli import app

def test_full_workflow(runner, tmp_path):
    """Test the full init -> validate -> run workflow."""
    with runner.isolated_filesystem(temp_dir=tmp_path):
        # 1. Initialize project
        result = runner.invoke(app, ["init", "."])
        assert result.exit_code == 0
        assert (tmp_path / "raicb.yaml").exists()

        # 2. Validate configuration
        result = runner.invoke(app, ["validate"])
        assert result.exit_code == 0
        assert "Configuration is valid" in result.stdout

        # 3. Run assessment (expect failures as sample project is empty/dummy)
        # We disable fail-on to ensure exit code 0 if checks run but fail
        result = runner.invoke(app, ["run", "--fail-on", "none"])
        
        # Depending on environment, check modules might fail (e.g. missing tools)
        # But we expect the command to complete execution
        assert "Assessment Complete" in result.stdout
        assert (tmp_path / "reports").exists()

