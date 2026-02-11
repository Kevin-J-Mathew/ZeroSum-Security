#!/usr/bin/env python3
"""
Convert markdown tables to images
"""

import matplotlib.pyplot as plt
import pandas as pd
from pathlib import Path
import re

# Set professional matplotlib style
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica']
plt.rcParams['figure.facecolor'] = 'white'
plt.rcParams['axes.facecolor'] = 'white'
plt.rcParams['savefig.facecolor'] = 'white'
plt.rcParams['savefig.edgecolor'] = 'none'
plt.rcParams['text.antialiased'] = True

def parse_markdown_table(md_text):
    """Parse a markdown table into a pandas DataFrame"""
    lines = [l.strip() for l in md_text.strip().split('\n') if l.strip()]
    
    # Remove leading/trailing pipes and split
    headers = [h.strip() for h in lines[0].split('|')[1:-1]]
    
    # Skip separator line (line 1)
    rows = []
    for line in lines[2:]:
        row = [cell.strip() for cell in line.split('|')[1:-1]]
        rows.append(row)
    
    return pd.DataFrame(rows, columns=headers)

def render_table_as_image(df, title, output_path, figsize=(14, 7)):
    """Render a pandas DataFrame as a professional-looking image"""
    
    # Create figure with modern styling
    fig, ax = plt.subplots(figsize=figsize, facecolor='white')
    ax.axis('tight')
    ax.axis('off')
    
    # Calculate column widths dynamically
    col_widths = []
    for col in df.columns:
        max_len = max(df[col].astype(str).str.len().max(), len(col))
        col_widths.append(max(0.8, min(max_len * 0.12, 3.0)))
    total_width = sum(col_widths)
    col_widths = [w/total_width for w in col_widths]
    
    # Create table
    table = ax.table(
        cellText=df.values,
        colLabels=df.columns,
        cellLoc='center',
        loc='center',
        colWidths=col_widths,
        bbox=[0, 0, 1, 1]
    )
    
    # Modern styling
    table.auto_set_font_size(False)
    table.set_fontsize(12)
    table.scale(1, 2.5)
    
    # Professional header styling with gradient effect
    for i in range(len(df.columns)):
        cell = table[(0, i)]
        cell.set_facecolor('#1f77b4')  # Professional blue
        cell.set_text_props(weight='bold', color='white', fontsize=14, family='sans-serif')
        cell.set_edgecolor('white')
        cell.set_linewidth(2)
        cell.set_height(0.08)
    
    # Modern row styling
    for i in range(1, len(df) + 1):
        for j in range(len(df.columns)):
            cell = table[(i, j)]
            text = cell.get_text().get_text()
            
            # Base color (subtle alternating)
            if i % 2 == 0:
                base_color = '#f8f9fa'
            else:
                base_color = 'white'
            
            # Status-specific highlighting
            if 'PASS' in text:
                cell.set_facecolor('#d4edda')  # Soft green
                cell.set_text_props(weight='bold', color='#155724', fontsize=12)
            elif 'FAIL' in text:
                cell.set_facecolor('#f8d7da')  # Soft red
                cell.set_text_props(weight='bold', color='#721c24', fontsize=12)
            elif 'WARN' in text:
                cell.set_facecolor('#fff3cd')  # Soft yellow
                cell.set_text_props(weight='bold', color='#856404', fontsize=12)
            else:
                cell.set_facecolor(base_color)
                cell.set_text_props(fontsize=11, family='sans-serif')
            
            # Professional borders
            cell.set_edgecolor('#dee2e6')
            cell.set_linewidth(1)
    
    # Add modern title with underline
    title_clean = title.replace('📊', '').replace('🔒', '').replace('📈', '').replace('✅', '').strip()
    plt.text(0.5, 0.98, title_clean, 
             horizontalalignment='center',
             verticalalignment='top',
             transform=fig.transFigure,
             fontsize=18, 
             fontweight='bold',
             family='sans-serif',
             color='#212529')
    
    # Add subtle shadow effect (decorative line)
    ax.add_patch(plt.Rectangle((0, -0.02), 1, 0.005, 
                               transform=ax.transAxes,
                               color='#dee2e6', 
                               zorder=1000))
    
    # Save with high quality
    plt.savefig(output_path, dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none', pad_inches=0.3)
    plt.close()
    
    print(f"✓ Saved: {output_path}")

def extract_tables_from_markdown(md_file):
    """Extract all tables from markdown file"""
    
    with open(md_file, 'r') as f:
        content = f.read()
    
    # Find all sections with tables
    sections = re.split(r'##\s+', content)[1:]  # Skip before first ##
    
    tables = []
    for section in sections:
        lines = section.split('\n')
        title = lines[0].strip()
        
        # Find table blocks (lines starting with |)
        table_lines = []
        in_table = False
        
        for line in lines[1:]:
            if line.strip().startswith('|'):
                in_table = True
                table_lines.append(line)
            elif in_table and not line.strip().startswith('|'):
                # End of table
                if table_lines:
                    table_text = '\n'.join(table_lines)
                    tables.append((title, table_text))
                    table_lines = []
                    in_table = False
        
        # Catch last table in section
        if table_lines:
            table_text = '\n'.join(table_lines)
            tables.append((title, table_text))
    
    return tables

def main():
    md_file = Path('experiments/results/visualizations/EVALUATION_REPORT.md')
    output_dir = Path('experiments/results/visualizations/tables')
    output_dir.mkdir(exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"MARKDOWN TABLES TO IMAGES")
    print(f"{'='*60}\n")
    print(f"Reading: {md_file}\n")
    
    if not md_file.exists():
        print(f"Error: {md_file} not found!")
        print("Run generate_detailed_analysis.py first.")
        return
    
    # Extract tables
    tables = extract_tables_from_markdown(md_file)
    
    print(f"Found {len(tables)} tables\n")
    
    # Convert each table to image
    for i, (title, table_md) in enumerate(tables, 1):
        try:
            df = parse_markdown_table(table_md)
            
            # Clean emoji from title for filename
            clean_title = re.sub(r'[^\w\s-]', '', title).strip().replace(' ', '_')
            output_path = output_dir / f"{i:02d}_{clean_title}.png"
            
            # Adjust figsize based on table dimensions
            rows, cols = df.shape
            figsize = (max(12, cols * 3), max(5, rows * 0.6 + 3))
            
            render_table_as_image(df, title, output_path, figsize)
            
        except Exception as e:
            print(f"⚠️  Failed to convert table '{title}': {e}")
    
    print(f"\n{'='*60}")
    print(f"COMPLETE")
    print(f"{'='*60}\n")
    print(f"Tables saved to: {output_dir}/\n")
    print("View tables:")
    print(f"  ls {output_dir}")

if __name__ == "__main__":
    main()
