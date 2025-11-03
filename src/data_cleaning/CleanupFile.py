import os
import sys
from typing import List
import pandas as pd
import numpy as np

# =======================
import os
import sys
from typing import List

import pandas as pd
import numpy as np


def clean_file(input_path: str, output_path: str) -> None:
    """Load, clean, and save the CSV at input_path to output_path."""
    print(f"Processing: {input_path}")
    df = pd.read_csv(input_path)
    print("  -> loaded, shape:", df.shape)
    
    # Store original shape for comparison
    original_shape = df.shape
    
    # 1. Process timestamp columns first (for time-based queries)
    timestamp_cols = [col for col in df.columns if 'time' in col.lower()]
    for col in timestamp_cols:
        if df[col].dtype == 'object':
            try:
                df[col] = pd.to_datetime(df[col])
                # Add day of week for easier querying
                df[f'{col}_dayofweek'] = df[col].dt.day_name()
                print(f"  Processed timestamp column: {col}")
            except Exception as e:
                print(f"  Could not process timestamp column {col}: {e}")
    
    # 2. Clean IP addresses
    ip_cols = [col for col in df.columns if 'ip' in col.lower()]
    for col in ip_cols:
        if df[col].dtype == 'object':
            # Remove whitespace and validate IP format
            df[col] = df[col].str.strip()
            # Basic IP validation
            mask = df[col].str.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            invalid_ips = (~mask).sum()
            if invalid_ips > 0:
                print(f"  Found {invalid_ips} invalid IPs in {col}")
                df = df[mask]
    
    # 3. Clean ports
    port_cols = [col for col in df.columns if 'port' in col.lower()]
    for col in port_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
        invalid_ports = (~df[col].between(0, 65535)).sum()
        if invalid_ports > 0:
            print(f"  Found {invalid_ports} invalid ports in {col}")
            df = df[df[col].between(0, 65535)]
    
    # 4. Handle missing and infinite values
    print("  Checking for missing and infinite values...")
    missing = df.isna().sum()
    if missing.sum() > 0:
        print("  Columns with missing values:\n", missing[missing > 0])
    
    # Replace infinity values with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Handle missing values based on column type
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        if df[col].isnull().any():
            if any(x in col.lower() for x in ['packet', 'byte', 'length']):
                df[col] = df[col].fillna(0)
            else:
                df[col] = df[col].fillna(df[col].median())
    
    # For categorical columns use mode
    cat_cols = df.select_dtypes(include=['object']).columns
    for col in cat_cols:
        if df[col].isnull().any():
            df[col] = df[col].fillna(df[col].mode()[0])
    
    # 5. Remove duplicates
    dup_before = df.shape[0]
    df.drop_duplicates(inplace=True)
    dup_after = df.shape[0]
    print(f"  Removed {dup_before - dup_after} duplicate rows")
    
    # 6. Handle extreme outliers in numeric columns
    for col in numeric_cols:
        # Skip certain columns where outliers might be legitimate
        if any(x in col.lower() for x in ['port', 'protocol']):
            continue
        
        Q1 = df[col].quantile(0.25)
        Q3 = df[col].quantile(0.75)
        IQR = Q3 - Q1
        lower = Q1 - 3 * IQR
        upper = Q3 + 3 * IQR
        outliers = ((df[col] < lower) | (df[col] > upper)).sum()
        if outliers > 0:
            print(f"  Removing {outliers} outliers from {col}")
            df = df[(df[col] >= lower) & (df[col] <= upper)]
    
    # 7. Normalize string columns
    for col in cat_cols:
        df[col] = df[col].str.lower().str.strip()
    
    # Print summary
    print("\nCleaning Summary:")
    print(f"  Original shape: {original_shape}")
    print(f"  Final shape: {df.shape}")
    print(f"  Rows removed: {original_shape[0] - df.shape[0]}")
    
    # Save cleaned CSV
    df.to_csv(output_path, index=False)
    print(f"  ✅ Cleaned CSV saved as: {output_path}\n")


def find_csv_files(folder: str) -> List[str]:
    return [os.path.join(folder, f) for f in os.listdir(folder) if f.lower().endswith('.csv')]


def main():
    # Resolve project and data folders
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    input_dir = os.path.join(project_root, "Extracted Data")
    output_dir = os.path.join(project_root, "Cleaned Data")
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")
    
    # Verify input directory exists
    if not os.path.exists(input_dir):
        raise FileNotFoundError(f"Input directory not found: {input_dir}")
    
    # Process all CSV files or specific file if provided
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if os.path.isabs(arg) and os.path.exists(arg):
            csvs = [arg]
        else:
            candidate = os.path.join(input_dir, arg)
            if os.path.exists(candidate):
                csvs = [candidate]
            else:
                raise FileNotFoundError(f"Provided file not found: {arg}")
    else:
        csvs = find_csv_files(input_dir)
    
    if not csvs:
        print("No CSV files found to process.")
        return
    
    print(f"Found {len(csvs)} CSV files to process")
    for csv in csvs:
        try:
            base = os.path.basename(csv)
            out_path = os.path.join(output_dir, f"cleaned_{base}")
            clean_file(csv, out_path)
        except Exception as e:
            print(f"Error processing {csv}: {e}")


if __name__ == '__main__':
    main()
