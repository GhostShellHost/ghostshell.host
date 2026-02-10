#!/bin/bash
set -e

# Find all HTML files
find . -name "*.html" -type f | while read -r file; do
    # Skip node_modules and .git
    if [[ "$file" == *"node_modules"* ]] || [[ "$file" == *".git"* ]]; then
        continue
    fi
    
    echo "Processing: $file"
    
    # Create backup
    cp "$file" "$file.bak"
    
    # Add timestamp footer before </body>
    # Use a unique marker to avoid multiple additions
    if grep -q "<!-- TIMESTAMP_FOOTER -->" "$file"; then
        echo "  Already has timestamp footer, updating..."
        # Remove existing footer
        sed -i '/<!-- TIMESTAMP_FOOTER -->/,/<!-- END_TIMESTAMP_FOOTER -->/d' "$file"
    fi
    
    # Add the footer before </body>
    sed -i 's|</body>|<!-- TIMESTAMP_FOOTER --><div style="position:fixed;bottom:0;right:0;background:#000;color:#fff;font-size:10px;padding:2px 4px;z-index:9999;opacity:0.7;font-family:monospace;">Deployed: 2026-02-11 00:40 GMT+10:30</div><!-- END_TIMESTAMP_FOOTER --></body>|' "$file"
    
    # Check if </body> exists
    if ! grep -q "</body>" "$file"; then
        echo "  Warning: No </body> tag found, appending at end"
        echo "<!-- TIMESTAMP_FOOTER --><div style=\"position:fixed;bottom:0;right:0;background:#000;color:#fff;font-size:10px;padding:2px 4px;z-index:9999;opacity:0.7;font-family:monospace;\">Deployed: 2026-02-11 00:40 GMT+10:30</div><!-- END_TIMESTAMP_FOOTER -->" >> "$file"
    fi
done

echo "Done!"