import pandas as pd
import numpy as np

# =======================
# 1. Load the CSV file
# =======================
import os

# Resolve path relative to this script so the script can be run from any CWD
script_dir = os.path.dirname(os.path.abspath(__file__))
file_name = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
# The dataset files live in the 'MachineLearningCVE' subfolder according to repo layout
file_path = os.path.join(script_dir, "MachineLearningCVE", file_name)

if not os.path.exists(file_path):
    raise FileNotFoundError(
        f"CSV file not found: {file_path}\nMake sure the file exists and the path is correct."
    )
df = pd.read_csv(file_path)
print("✅ File loaded successfully!")
print("Shape:", df.shape)
print("Columns:", list(df.columns))

# =======================
# 2. Check for Missing or Infinite Values
# =======================
print("\nChecking for missing and infinite values...")
missing = df.isna().sum()
print(missing[missing > 0])  # print columns with missing values

# Replace infinity values (like inf or -inf) with NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Drop rows with any missing values
df.dropna(inplace=True)

print("✅ After cleaning missing/infinite values:")
print("New shape:", df.shape)

# =======================
# 3. Remove Duplicate Rows
# =======================
before = df.shape[0]
df.drop_duplicates(inplace=True)
after = df.shape[0]
print(f"Removed {before - after} duplicate rows.")

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

    # 2. Check for Missing or Infinite Values
    print("  Checking for missing and infinite values...")
    missing = df.isna().sum()
    if missing.sum() > 0:
        print("  Columns with missing values:\n", missing[missing > 0])
    else:
        print("  No missing values detected.")

    # Replace infinity values (like inf or -inf) with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop rows with any missing values
    before = df.shape[0]
    df.dropna(inplace=True)
    after = df.shape[0]
    print(f"  ✅ After cleaning missing/infinite values: New shape: {df.shape}")

    # Remove duplicate rows
    dup_before = df.shape[0]
    df.drop_duplicates(inplace=True)
    dup_after = df.shape[0]
    print(f"  Removed {dup_before - dup_after} duplicate rows.")

    # Identify and drop constant columns
    const_cols = [col for col in df.columns if df[col].nunique() <= 1]
    if const_cols:
        print("  Constant columns (dropped):", const_cols)
        df.drop(columns=const_cols, inplace=True)
    else:
        print("  No constant columns found.")

    # Print column dtypes
    print("  Column types:")
    print(df.dtypes)

    # Try converting object columns to numeric where possible
    for col in df.select_dtypes(include=['object']).columns:
        coerced = pd.to_numeric(df[col], errors='coerce')
        # If coercing doesn't produce many NaNs, replace the column
        if coerced.notna().sum() >= 0.9 * len(coerced):
            df[col] = coerced

    # Preview
    print("\n  Preview of cleaned dataset:")
    print(df.head())

    # Save cleaned CSV
    df.to_csv(output_path, index=False)
    print(f"  ✅ Cleaned CSV saved as: {output_path}\n")


def find_csv_files(folder: str) -> List[str]:
    return [os.path.join(folder, f) for f in os.listdir(folder) if f.lower().endswith('.csv')]


def main():
    # Resolve project and data folder
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, "MachineLearningCVE")

    # Accept optional filename as CLI argument (basename only or path)
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if os.path.isabs(arg) and os.path.exists(arg):
            csvs = [arg]
        else:
            candidate = os.path.join(data_dir, arg)
            if os.path.exists(candidate):
                csvs = [candidate]
            else:
                candidate2 = os.path.join(data_dir, os.path.basename(arg))
                if os.path.exists(candidate2):
                    csvs = [candidate2]
                else:
                    raise FileNotFoundError(f"Provided file not found: {arg}")
    else:
        if not os.path.exists(data_dir):
            raise FileNotFoundError(f"Data directory not found: {data_dir}")
        csvs = find_csv_files(data_dir)

    if not csvs:
        print("No CSV files found to process.")
        return

    for csv in csvs:
        try:
            base = os.path.basename(csv)
            out_name = f"cleaned_{base}"
            out_path = os.path.join(script_dir, out_name)
            clean_file(csv, out_path)
        except Exception as e:
            print(f"Error processing {csv}: {e}")


if __name__ == '__main__':
    main()
