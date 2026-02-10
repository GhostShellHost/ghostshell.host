#!/bin/bash
set -e

# Files we want to KEEP timestamps on (the 4 we changed)
KEEP_FILES=(
  "index.html"
  "issue/index.html"
  "index_test/index.html"
  "archive/index.html"
)

# Find all HTML files with timestamp footer
find . -name "*.html" -type f ! -path "*/node_modules/*" ! -path "*/.git/*" | while read -r file; do
    # Get relative path
    rel_path="${file#./}"
    
    # Check if this file is in our keep list
    keep=0
    for keep_file in "${KEEP_FILES[@]}"; do
        if [[ "$rel_path" == "$keep_file" ]]; then
            keep=1
            break
        fi
    done
    
    if [[ $keep -eq 1 ]]; then
        echo "Keeping timestamp on: $rel_path"
    else
        echo "Removing timestamp from: $rel_path"
        # Remove timestamp footer
        sed -i '/<!-- TIMESTAMP_FOOTER -->/,/<!-- END_TIMESTAMP_FOOTER -->/d' "$file"
    fi
done

echo "Done!"