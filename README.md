# Flow Log Parser

This Python script parses AWS VPC flow logs, matches each log entry to a tag using a lookup table, and then counts how many times each tag and port/protocol combination appears.

## Requirements

- Python 3.6 or higher
- No external libraries are needed

## How to Run

1. Make sure you have two files in the same directory as the script:
   - `flow_logs.txt`: The file with your flow log data.
   - `lookup_table.csv`: The CSV file that maps ports and protocols to tags.

2. Run the script using Python:
   ```bash
   python flow_log_parser.py
   ```
The output will be saved in a file called `output.txt` in the same directory.

## Assumptions

- The script supports only the default AWS VPC flow log format (version 2).
- The flow log file is plain text, with each log entry on a new line.
- The lookup table is a CSV file with three columns: `dstport`, `protocol`, and `tag`.
- The destination port is taken from the 7th field in the flow log entry.
- The protocol is identified by the 8th field: `6` for TCP, `17` for UDP, and others for ICMP.
- Matching is case-insensitive.
- The flow log file size can be up to 10 MB 
- The script expects the flow log and lookup table files to be small enough to load into memory.

## Testing

- A test script (`test_flow_log_parser.py`) is included to check the main script.
- To run the tests, use:
  ```bash
  python -m unittest test_flow_log_parser.py
  ```

## Limitations
The entire lookup table is loaded into memory, which might not scale well with very large files.
Error handling is basic; the script skips malformed lines and prints a warning.

## Potential Improvements

Allow input/output file paths to be specified as command-line arguments.
Improve logging and error handling for production use.
Optimize memory usage for handling larger files.
