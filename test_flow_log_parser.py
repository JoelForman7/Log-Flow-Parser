import unittest
import tempfile
import os
from flow_log_parser import read_lookup_table, parse_flow_log, match_tag, process_flow_logs

class TestFlowLogParser(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        
        self.lookup_path = os.path.join(self.temp_dir, 'lookup.csv')
        with open(self.lookup_path, 'w') as f:
            f.write("dstport,protocol,tag\n")
            f.write("45678,tcp,web\n")
            f.write("45679,tcp,web_secure\n")
            f.write("45680,udp,dns\n")

        self.flow_log_path = os.path.join(self.temp_dir, 'flow_log.txt')
        with open(self.flow_log_path, 'w') as f:
            f.write("2 123456789012 eni-1234567890 10.0.0.1 10.0.0.2 80 45678 6 10 1000 1623456789 1623456799 ACCEPT OK\n")
            f.write("2 123456789012 eni-1234567890 10.0.0.1 10.0.0.3 443 45679 6 15 1500 1623456790 1623456800 ACCEPT OK\n")
            f.write("2 123456789012 eni-1234567890 10.0.0.1 10.0.0.4 53 45680 17 5 500 1623456791 1623456801 ACCEPT OK\n")
            f.write("2 123456789012 eni-1234567890 10.0.0.1 10.0.0.5 22 45681 6 8 800 1623456792 1623456802 ACCEPT OK\n")

    def test_read_lookup_table(self):
        lookup = read_lookup_table(self.lookup_path)
        self.assertEqual(len(lookup), 3)
        self.assertIn((45678, 'tcp'), lookup['web'])
        self.assertIn((45679, 'tcp'), lookup['web_secure'])
        self.assertIn((45680, 'udp'), lookup['dns'])

    def test_parse_flow_log(self):
        with open(self.flow_log_path, 'r') as f:
            line = f.readline()
        flow = parse_flow_log(line)
        self.assertEqual(flow['dstport'], 45678)
        self.assertEqual(flow['protocol'], 'tcp')

    def test_match_tag(self):
        lookup = read_lookup_table(self.lookup_path)
        flow1 = {'dstport': 45678, 'protocol': 'tcp'}
        flow2 = {'dstport': 45681, 'protocol': 'tcp'}
        self.assertEqual(match_tag(flow1, lookup), 'web')
        self.assertEqual(match_tag(flow2, lookup), 'Untagged')

    def test_process_flow_logs(self):
        tag_counts, port_protocol_counts = process_flow_logs(self.flow_log_path, self.lookup_path)
        self.assertEqual(tag_counts['web'], 1)
        self.assertEqual(tag_counts['web_secure'], 1)
        self.assertEqual(tag_counts['dns'], 1)
        self.assertEqual(tag_counts['Untagged'], 1)
        self.assertEqual(port_protocol_counts[(45678, 'tcp')], 1)
        self.assertEqual(port_protocol_counts[(45679, 'tcp')], 1)
        self.assertEqual(port_protocol_counts[(45680, 'udp')], 1)
        self.assertEqual(port_protocol_counts[(45681, 'tcp')], 1)

    def tearDown(self):
        os.remove(self.lookup_path)
        os.remove(self.flow_log_path)
        os.rmdir(self.temp_dir)

if __name__ == '__main__':
    unittest.main()