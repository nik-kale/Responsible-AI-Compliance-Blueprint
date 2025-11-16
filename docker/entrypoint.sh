#!/bin/bash
set -e

# Check MODE environment variable
if [ "$MODE" = "ui" ]; then
    echo "Starting Streamlit UI..."
    exec streamlit run /app/app/streamlit_app.py \
        --server.port=8501 \
        --server.address=0.0.0.0 \
        --server.headless=true \
        --browser.gatherUsageStats=false
else
    # CLI mode
    echo "Running in CLI mode..."
    exec raicb "$@"
fi
