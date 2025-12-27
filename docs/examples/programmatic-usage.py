from pathlib import Path
from raicb.core.loader import load_config
from raicb.core.evaluator import run_all_checks

def main():
    config_path = Path("raicb.yaml")
    config = load_config(config_path)
    
    report = run_all_checks(config, Path("."), "prod")
    
    print(f"Total checks: {report.total_checks}")
    print(f"Failed checks: {report.failed_checks}")

if __name__ == "__main__":
    main()

