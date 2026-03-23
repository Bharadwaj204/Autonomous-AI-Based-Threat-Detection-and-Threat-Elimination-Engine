"""
STEP 2 + 3: CIC-IDS2017 Feature Transformation Pipeline
- Reads all 8 CSV files
- Drops duplicates, handles nulls/infinities
- Maps CICIDS features to the 6 Autonomous AI Based Threat Detection and Threat Elimination Engine features
- Saves processed_cicids_training_data.csv

Feature Mapping:
  cpu_usage        ← Fwd Packet Length Std + Bwd Packet Length Std (proxy for processing load)
  memory_usage     ← Packet Length Variance (normalised to 0-100 scale)
  entropy          ← Fwd Packet Length Std / 8 (0-8 entropy proxy)
  packet_rate      ← Flow Packets/s
  bytes_per_sec    ← Flow Bytes/s
  connection_count ← Total Fwd Packets + Total Backward Packets

  label            ← BENIGN=0, everything else=1
"""
import os
import sys
import math
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

# ── Config ────────────────────────────────────────────────────────────────────
INPUT_DIR  = os.path.join(os.path.dirname(__file__), 'CIC-IDS2017')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
OUTPUT_CSV = os.path.join(OUTPUT_DIR, 'processed_cicids_training_data.csv')
MAX_ROWS_PER_CLASS = 100_000   # Cap per class for manageable file size
SAMPLE_SEED = 42

os.makedirs(OUTPUT_DIR, exist_ok=True)

# CICIDS column names (stripped)
COL_FWD_PKT_STD  = 'Fwd Packet Length Std'
COL_BWD_PKT_STD  = 'Bwd Packet Length Std'
COL_PKT_VAR      = 'Packet Length Variance'
COL_PKT_STD      = 'Packet Length Std'
COL_FLOW_PKTS    = 'Flow Packets/s'
COL_FLOW_BYTES   = 'Flow Bytes/s'
COL_FWD_PKTS     = 'Total Fwd Packets'
COL_BWD_PKTS     = 'Total Backward Packets'
COL_LABEL        = 'Label'

OUTPUT_COLS = ['cpu_usage', 'memory_usage', 'entropy',
               'packet_rate', 'bytes_per_sec', 'connection_count', 'is_threat']


def clamp(series: pd.Series, lo: float, hi: float) -> pd.Series:
    return series.clip(lo, hi)


def transform_chunk(df: pd.DataFrame) -> pd.DataFrame:
    """Map CICIDS columns → Autonomous AI Based Threat Detection and Threat Elimination Engine feature space."""
    df.columns = [c.strip() for c in df.columns]

    # --- Binary label -------------------------------------------------------
    df['is_threat'] = (df[COL_LABEL].str.strip().str.upper() != 'BENIGN').astype(int)

    # --- Feature mapping ----------------------------------------------------
    # cpu_usage: average packet processing burden (Fwd+Bwd Std, normalised 0-100)
    fwd_std = df[COL_FWD_PKT_STD].fillna(0).clip(0, 1000)
    bwd_std = df.get(COL_BWD_PKT_STD, pd.Series(0, index=df.index)).fillna(0).clip(0, 1000)
    cpu = ((fwd_std + bwd_std) / 2) / 10   # ~0-100 range
    df['cpu_usage'] = clamp(cpu, 0, 100)

    # memory_usage: packet length variance proxy (normalised to 0-100)
    pkt_var = df.get(COL_PKT_VAR, pd.Series(0, index=df.index)).fillna(0).clip(0, 1_000_000)
    df['memory_usage'] = clamp(pkt_var / 10_000, 0, 100)   # scale: 1M→100

    # entropy: Packet Length Std as entropy proxy (0-8 range, like Shannon entropy)
    pkt_std = df.get(COL_PKT_STD, fwd_std).fillna(0).clip(0, 400)
    df['entropy'] = clamp(pkt_std / 50.0, 0, 8.0)          # 400 std → 8.0 entropy

    # packet_rate: direct mapping (packets/s)
    df['packet_rate'] = df[COL_FLOW_PKTS].fillna(0).clip(0, 1_000_000).replace([np.inf, -np.inf], 0)

    # bytes_per_sec: direct mapping
    df['bytes_per_sec'] = df[COL_FLOW_BYTES].fillna(0).clip(0, 10_000_000).replace([np.inf, -np.inf], 0)

    # connection_count: total packets in flow (fwd + backward)
    fwd_pkts = df[COL_FWD_PKTS].fillna(0).clip(0, 10_000)
    bwd_pkts = df.get(COL_BWD_PKTS, pd.Series(0, index=df.index)).fillna(0).clip(0, 10_000)
    df['connection_count'] = fwd_pkts + bwd_pkts

    # --- Select output columns ----------------------------------------------
    return df[OUTPUT_COLS].dropna()


def main():
    print("=" * 60)
    print("  CIC-IDS2017 Feature Transformation Pipeline")
    print("=" * 60)

    csv_files = [f for f in sorted(os.listdir(INPUT_DIR)) if f.endswith('.csv')]
    print(f"\nFound {len(csv_files)} CSV files in {INPUT_DIR}")

    all_chunks = []
    total_raw = 0

    for fname in csv_files:
        path = os.path.join(INPUT_DIR, fname)
        print(f"\nProcessing: {fname}")
        try:
            df = pd.read_csv(path, low_memory=False)
            df.columns = [c.strip() for c in df.columns]
            print(f"  Raw rows: {len(df):,}  |  Cols: {len(df.columns)}")

            # Drop infs and exact duplicates
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            dups = df.duplicated().sum()
            df.drop_duplicates(inplace=True)
            print(f"  Dropped {dups:,} duplicates  →  {len(df):,} rows remain")

            chunk = transform_chunk(df)
            total_raw += len(chunk)
            print(f"  Transformed rows: {len(chunk):,}")
            print(f"  Class split → {(chunk['is_threat']==0).sum():,} BENIGN, "
                  f"{(chunk['is_threat']==1).sum():,} ATTACK")
            all_chunks.append(chunk)

        except Exception as e:
            print(f"  ERROR: {e}")

    # ── Combine all files ────────────────────────────────────────────────────
    print(f"\nCombining all chunks: {total_raw:,} rows total …")
    combined = pd.concat(all_chunks, ignore_index=True)

    # ── Separate classes ─────────────────────────────────────────────────────
    benign  = combined[combined['is_threat'] == 0]
    attacks = combined[combined['is_threat'] == 1]

    print(f"\nBefore balancing:")
    print(f"  BENIGN:  {len(benign):,}")
    print(f"  ATTACKS: {len(attacks):,}")

    # ── Stratified sampling for balanced, manageable dataset ─────────────────
    n_benign  = min(len(benign),  MAX_ROWS_PER_CLASS)
    n_attacks = min(len(attacks), MAX_ROWS_PER_CLASS)

    sampled_benign  = benign.sample(n=n_benign,  random_state=SAMPLE_SEED)
    sampled_attacks = attacks.sample(n=n_attacks, random_state=SAMPLE_SEED)

    final = pd.concat([sampled_benign, sampled_attacks], ignore_index=True)
    final = final.sample(frac=1, random_state=SAMPLE_SEED).reset_index(drop=True)

    print(f"\nAfter balanced sampling (max {MAX_ROWS_PER_CLASS:,} per class):")
    print(f"  BENIGN:  {(final['is_threat']==0).sum():,}")
    print(f"  ATTACKS: {(final['is_threat']==1).sum():,}")
    print(f"  TOTAL:   {len(final):,}")

    # ── Feature statistics ───────────────────────────────────────────────────
    print("\n=== Feature Statistics ===")
    print(final[OUTPUT_COLS[:-1]].describe().round(3).to_string())

    # ── Missing values check ─────────────────────────────────────────────────
    nulls = final.isnull().sum()
    print(f"\nMissing values: {nulls.to_dict()}")

    # ── Save ─────────────────────────────────────────────────────────────────
    final.to_csv(OUTPUT_CSV, index=False)
    print(f"\n✅ Saved {len(final):,} rows to: {OUTPUT_CSV}")
    print("\nColumn dtypes:")
    print(final.dtypes.to_string())

    return len(final)


if __name__ == '__main__':
    main()
