import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from rich.console import Console

from raicb.core.evaluator import run_all_checks
from raicb.core.loader import load_config

console = Console()

class ComplianceChangeHandler(FileSystemEventHandler):
    def __init__(self, config_path: Path, env: str, project_root: Path):
        self.config_path = config_path
        self.env = env
        self.project_root = project_root
        self.last_run = 0
        self.debounce_seconds = 1.0

    def on_modified(self, event):
        if event.is_directory:
            return
        
        # Debounce
        current_time = time.time()
        if current_time - self.last_run < self.debounce_seconds:
            return
        
        filename = Path(event.src_path).name
        if filename.endswith(('.yaml', '.py', '.md')):
            console.print(f"\n[bold yellow]Change detected in {filename}. Re-running checks...[/bold yellow]")
            self.run_checks()
            self.last_run = time.time()

    def run_checks(self):
        try:
            # Reload config in case it changed
            config = load_config(self.config_path)
            run_all_checks(
                config, 
                self.project_root, 
                self.env, 
                verbose=False, 
                use_cache=True, 
                config_path=self.config_path
            )
        except Exception as e:
            console.print(f"[red]Error running checks: {e}[/red]")

def start_watch_mode(config_path: Path, env: str, project_root: Path):
    """Start watching file system for changes."""
    event_handler = ComplianceChangeHandler(config_path, env, project_root)
    observer = Observer()
    observer.schedule(event_handler, str(project_root), recursive=True)
    observer.start()
    
    console.print(f"[bold green]Watching for changes in {project_root}...[/bold green]")
    console.print("Press Ctrl+C to stop.")
    
    # Run initial check
    event_handler.run_checks()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

