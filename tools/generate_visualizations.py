import pandas as pd
import matplotlib.pyplot as plt
import os
import argparse

from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

# Set aesthetics for "Academic/Paper" look
plt.style.use('ggplot')
plt.rcParams.update({'font.size': 12, 'figure.figsize': (10, 6)})

def safe_load_csv(filepath):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return None
    try:
        return pd.read_csv(filepath, on_bad_lines='skip')
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return None

def get_true_label(sample_name):
    """
    Infers the true label from the sample name.
    """
    sample_name = str(sample_name).lower()
    # Check for specific malware keywords
    if 'malicious_intent' in sample_name or 'compromised_lib' in sample_name or 'malware' in sample_name:
        return 'Malicious'
    # Check for date-prefixed generated malware samples (e.g., 2025-11-24-...)
    if sample_name.startswith(('2023-', '2024-', '2025-')):
        return 'Malicious'
    # Check for synthetic benign baseline
    if 'benign_baseline' in sample_name:
        return 'Benign'
    return 'Benign'

def get_predicted_label(verdict):
    """
    Maps scanner verdict to 'Malicious' (Blocked) or 'Benign' (Allowed).
    """
    if verdict == 'BLOCKED':
        return 'Malicious'
    return 'Benign'

def plot_confusion_matrix_chart(df, ecosystem, output_dir):
    try:
        y_true = df['package'].apply(get_true_label)
        y_pred = df['verdict'].apply(get_predicted_label)
        
        cm = confusion_matrix(y_true, y_pred, labels=['Benign', 'Malicious'])
        
        # Plot
        plt.figure(figsize=(8, 6))
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Benign', 'Malicious'])
        disp.plot(cmap='Blues', values_format='d')
        plt.title(f"{ecosystem} Confusion Matrix")
        plt.grid(False) # Disable grid for CM
        
        filename = f"{ecosystem.lower()}_confusion_matrix.png"
        save_path = os.path.join(output_dir, filename)
        plt.savefig(save_path)
        print(f"Saved: {save_path}")
        plt.close()
    except Exception as e:
        print(f"Failed to generate confusion matrix for {ecosystem}: {e}")

def plot_verdict_distribution(df, ecosystem, output_dir):
    verdicts = df['verdict'].value_counts()
    
    plt.figure(figsize=(8, 8))
    
    # Paper-friendly colors
    colors = {
        'BLOCKED': '#d62728', # Red
        'WARNING': '#ff7f0e', # Orange
        'SAFE': '#2ca02c',    # Green
        'ERROR': '#7f7f7f',   # Gray
        'TIMEOUT': '#7f7f7f'
    }
    
    # Map colors to index
    pie_colors = [colors.get(v, '#333333') for v in verdicts.index]
    
    plt.pie(verdicts, labels=verdicts.index, autopct='%1.1f%%', startangle=140, colors=pie_colors)
    plt.title(f"{ecosystem} Detection Verdicts (N={len(df)})")
    
    filename = f"{ecosystem.lower()}_verdicts.png"
    save_path = os.path.join(output_dir, filename)
    plt.savefig(save_path)
    print(f"Saved: {save_path}")
    plt.close()

def plot_score_histogram(df, ecosystem, output_dir):
    plt.figure(figsize=(10, 6))
    
    # Filter valid scores
    scores = df['score'].dropna()
    
    # Plot
    plt.hist(scores, bins=30, color="skyblue", edgecolor='black')
    
    # Threshold lines
    plt.axvline(x=3.5, color='green', linestyle='--', label='Safe Threshold (3)')
    plt.axvline(x=9.5, color='red', linestyle='--', label='Block Threshold (10)')
    
    plt.title(f"{ecosystem} Risk Score Distribution")
    plt.xlabel("Risk Score")
    plt.ylabel("Count")
    plt.legend()
    
    filename = f"{ecosystem.lower()}_scores.png"
    save_path = os.path.join(output_dir, filename)
    plt.savefig(save_path)
    print(f"Saved: {save_path}")
    plt.close()

def main():
    parser = argparse.ArgumentParser(description="Generate Research Charts")
    parser.add_argument("--npm", help="Path to NPM results CSV", default=None)
    parser.add_argument("--pypi", help="Path to PyPI results CSV", default=None)
    parser.add_argument("--benign", help="Path to Benign results CSV", default=None)
    parser.add_argument("--out", help="Output directory", default="docs/images")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    if args.npm:
        print("Processing NPM Data...")
        df_npm = safe_load_csv(args.npm)
        if df_npm is not None:
            # Load real benign data if available
            if args.benign:
                print("  [+] Loading real benign dataset...")
                df_benign = safe_load_csv(args.benign)
                if df_benign is not None:
                    # Merge for authentic confusion matrix
                    df_npm_with_benign = pd.concat([df_npm, df_benign], ignore_index=True)
                    print(f"  [+] Merged: {len(df_npm)} malware + {len(df_benign)} benign = {len(df_npm_with_benign)} total")
                else:
                    df_npm_with_benign = df_npm
            else:
                df_npm_with_benign = df_npm
            
            plot_verdict_distribution(df_npm, "NPM", args.out)
            plot_score_histogram(df_npm, "NPM", args.out)
            plot_confusion_matrix_chart(df_npm_with_benign, "NPM", args.out)

    if args.pypi:
        print("Processing PyPI Data...")
        df_pypi = safe_load_csv(args.pypi)
        if df_pypi is not None:
            plot_verdict_distribution(df_pypi, "PyPI", args.out)
            plot_score_histogram(df_pypi, "PyPI", args.out)
            plot_confusion_matrix_chart(df_pypi, "PyPI", args.out)

    print("Visualization generation complete.")

def augment_with_benign_data(df, count=5000):
    """
    Injects synthetic benign data to represent testing against safe packages 
    (e.g., top 5k NPM packages) which are presumed SAFE.
    """
    print(f"  [+] Augmenting with {count} Benign samples (Simulated Baseline)...")
    benign_rows = []
    for i in range(count):
        benign_rows.append({
            'package': f'benign_baseline_lib_{i}', 
            'verdict': 'SAFE', 
            'score': 0
        })
    
    benign_df = pd.DataFrame(benign_rows)
    return pd.concat([df, benign_df], ignore_index=True)

if __name__ == "__main__":
    main()
