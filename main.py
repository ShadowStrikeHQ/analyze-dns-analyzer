import argparse
import logging
import pandas as pd
import sys
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the DNS analyzer.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Analyzes DNS traffic for suspicious patterns like DGAs and fast-flux DNS.")
    parser.add_argument("dns_log_file", help="Path to the DNS log file (e.g., in CSV or text format).", type=str)
    parser.add_argument("--domain_threshold", help="Threshold for considering a domain potentially DGA-generated (length).", type=int, default=20) # Example threshold
    parser.add_argument("--ip_change_threshold", help="Threshold for considering a domain as fast-flux (number of IP changes).", type=int, default=10) # Example threshold
    parser.add_argument("--output_file", help="Path to save the analysis results (CSV format).", type=str, default="dns_analysis_results.csv")
    parser.add_argument("--debug", help="Enable debug logging.", action="store_true") # for debugging
    return parser

def load_dns_data(dns_log_file):
    """
    Loads DNS data from a CSV or text file into a Pandas DataFrame.
    Handles potential errors related to file loading.

    Args:
        dns_log_file (str): Path to the DNS log file.

    Returns:
        pandas.DataFrame: A DataFrame containing the DNS data, or None if an error occurred.
    """
    try:
        # Attempt to read as CSV
        try:
            df = pd.read_csv(dns_log_file)
            logging.info(f"Successfully loaded DNS data from CSV file: {dns_log_file}")
            return df
        except pd.errors.ParserError:  # Handle CSV parsing errors
            # Attempt to read as a text file (assuming space-separated values)
            try:
                df = pd.read_csv(dns_log_file, sep='\s+')  # Try space-separated
                logging.info(f"Successfully loaded DNS data from text file (space-separated): {dns_log_file}")
                return df
            except pd.errors.ParserError:
                logging.error(f"Failed to parse DNS log file as either CSV or space-separated text: {dns_log_file}")
                return None
        except FileNotFoundError:
            logging.error(f"DNS log file not found: {dns_log_file}")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred while loading the DNS log file: {e}")
            return None

    except Exception as e:
        logging.error(f"Error loading DNS data: {e}")
        return None
def analyze_dga_domains(df, domain_threshold):
    """
    Analyzes DNS data for potential DGA-generated domains based on domain length.

    Args:
        df (pandas.DataFrame): DataFrame containing DNS data with a 'domain' column.
        domain_threshold (int): Threshold for domain length to be considered potentially DGA-generated.

    Returns:
        pandas.DataFrame: DataFrame containing potentially DGA-generated domains.
    """
    try:
        if 'domain' not in df.columns:
            logging.error("The 'domain' column is missing in the DNS data.")
            return pd.DataFrame()  # Return empty DataFrame to prevent errors
        
        dga_domains = df[df['domain'].str.len() > domain_threshold].copy() # Create a copy to avoid SettingWithCopyWarning
        if not dga_domains.empty:
             logging.info(f"Identified {len(dga_domains)} potentially DGA-generated domains (length > {domain_threshold}).")

        # Further DGA analysis can be added here (e.g., entropy analysis, character frequency analysis)
        dga_domains['dga_score'] = dga_domains['domain'].apply(calculate_dga_score)

        return dga_domains
    except Exception as e:
        logging.error(f"Error analyzing DGA domains: {e}")
        return pd.DataFrame()
    
def calculate_dga_score(domain):
    """
    Calculates a simplified DGA score based on character distribution
    """
    if not isinstance(domain, str):
        return 0 # Return 0 if it's not a string

    # Check for random character usage (simplified)
    # This checks for unusual combinations.
    # A real DGA analysis would be much more complex.

    score = 0
    # Check for digit usage
    if any(char.isdigit() for char in domain):
        score += 0.5

    # Check for repetitive characters
    for i in range(len(domain) - 2):
        if domain[i] == domain[i+1] == domain[i+2]:
            score += 0.3

    return score


def analyze_fast_flux(df, ip_change_threshold):
    """
    Analyzes DNS data for fast-flux DNS patterns based on IP address changes.

    Args:
        df (pandas.DataFrame): DataFrame containing DNS data with 'domain' and 'ip_address' columns.
        ip_change_threshold (int): Threshold for the number of IP changes to be considered fast-flux.

    Returns:
        pandas.DataFrame: DataFrame containing domains exhibiting fast-flux behavior.
    """
    try:
        required_columns = ['domain', 'ip_address']
        if not all(col in df.columns for col in required_columns):
            logging.error(f"Missing required columns for fast-flux analysis. Requires: {required_columns}")
            return pd.DataFrame()

        # Group by domain and count unique IP addresses
        ip_counts = df.groupby('domain')['ip_address'].nunique()

        # Filter domains with IP address changes exceeding the threshold
        fast_flux_domains = ip_counts[ip_counts > ip_change_threshold].index.to_list()

        fast_flux_df = df[df['domain'].isin(fast_flux_domains)].copy() # Create a copy to avoid SettingWithCopyWarning

        if not fast_flux_df.empty:
          logging.info(f"Identified {len(fast_flux_df['domain'].unique())} domains exhibiting fast-flux behavior (IP changes > {ip_change_threshold}).")
        return fast_flux_df

    except Exception as e:
        logging.error(f"Error analyzing fast-flux DNS: {e}")
        return pd.DataFrame()

def save_results(results_df, output_file):
    """
    Saves the analysis results to a CSV file. Handles potential errors.

    Args:
        results_df (pandas.DataFrame): DataFrame containing the analysis results.
        output_file (str): Path to the output CSV file.
    """
    try:
        results_df.to_csv(output_file, index=False)
        logging.info(f"Analysis results saved to: {output_file}")
    except Exception as e:
        logging.error(f"Error saving results to file: {output_file}. Error: {e}")

def main():
    """
    Main function to orchestrate the DNS analysis process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug mode enabled.")

    # Input Validation
    if not isinstance(args.dns_log_file, str) or not args.dns_log_file:
        logging.error("Invalid DNS log file path. Please provide a valid file path.")
        sys.exit(1)

    if args.domain_threshold <= 0:
        logging.error("Domain threshold must be a positive integer.")
        sys.exit(1)

    if args.ip_change_threshold <= 0:
        logging.error("IP change threshold must be a positive integer.")
        sys.exit(1)

    # Core Functionality
    dns_data = load_dns_data(args.dns_log_file)

    if dns_data is None or dns_data.empty:
        logging.error("No DNS data to analyze. Exiting.")
        sys.exit(1)

    dga_results = analyze_dga_domains(dns_data.copy(), args.domain_threshold)  # Pass a copy
    fast_flux_results = analyze_fast_flux(dns_data.copy(), args.ip_change_threshold) # Pass a copy

    # Combine results
    all_results = pd.concat([dga_results, fast_flux_results], ignore_index=True)

    # Remove duplicate rows based on all columns
    all_results = all_results.drop_duplicates()

    save_results(all_results, args.output_file)

    logging.info("DNS analysis complete.")

# Usage Examples (for documentation)
# Example 1: Analyze a DNS log file with default thresholds
# python dns_analyzer.py dns_log.csv

# Example 2: Analyze a DNS log file with custom thresholds
# python dns_analyzer.py dns_log.csv --domain_threshold 25 --ip_change_threshold 5

# Example 3: Analyze a DNS log file and save the results to a specific file
# python dns_analyzer.py dns_log.csv --output_file suspicious_dns.csv

# Example 4: Run in debug mode
# python dns_analyzer.py dns_log.csv --debug

if __name__ == "__main__":
    main()