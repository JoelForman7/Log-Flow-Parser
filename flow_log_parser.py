import csv
from collections import defaultdict

def read_lookup_table(file_path):
    lookup = defaultdict(list)
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (int(row['dstport']), row['protocol'].lower())
            lookup[row['tag']].append(key)
    return lookup

def parse_flow_log(line):
    fields = line.strip().split()
    if len(fields) < 14:
        print(f"Skipping malformed line: {line}")
        return None
    try:
        return {
            'dstport': int(fields[6]),
            'protocol': 'tcp' if fields[7] == '6' else 'udp' if fields[7] == '17' else 'icmp'
        }
    except ValueError:
        print(f"Unable to parse line: {line}")
        return None

def match_tag(flow, lookup):
    for tag, combinations in lookup.items():
        if (flow['dstport'], flow['protocol']) in combinations:
            return tag
    return 'Untagged'

def process_flow_logs(flow_log_path, lookup_table_path):
    lookup = read_lookup_table(lookup_table_path)
    tag_counts = defaultdict(int)
    port_protocol_counts = defaultdict(int)

    with open(flow_log_path, 'r') as f:
        for line in f:
            flow = parse_flow_log(line)
            if flow:
                tag = match_tag(flow, lookup)
                tag_counts[tag] += 1
                port_protocol_counts[(flow['dstport'], flow['protocol'])] += 1

    return tag_counts, port_protocol_counts

def generate_output(tag_counts, port_protocol_counts, output_file):
    with open(output_file, 'w') as f:
        f.write("Tag Counts:\n")
        f.write("Tag,Count\n")
        for tag, count in tag_counts.items():
            f.write(f"{tag},{count}\n")

        f.write("\nPort/Protocol Combination Counts:\n")
        f.write("Port,Protocol,Count\n")
        for (port, protocol), count in port_protocol_counts.items():
            f.write(f"{port},{protocol},{count}\n")

def main():
    flow_log_path = 'flow_logs.txt'
    lookup_table_path = 'lookup_table.csv'
    output_file = 'output.txt'

    tag_counts, port_protocol_counts = process_flow_logs(flow_log_path, lookup_table_path)
    generate_output(tag_counts, port_protocol_counts, output_file)

if __name__ == "__main__":
    main()