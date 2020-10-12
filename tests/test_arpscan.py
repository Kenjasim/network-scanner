import unittest, warnings
from scans import ARPScan

class ARPScanTest(unittest.TestCase):

    def setUp(self):
        """
        Surpress a benign warning which comes up 
        due to using sudo to run test
        """
        warnings.simplefilter('ignore', category=ResourceWarning)

    def test_successful_ip_network(self):
        """
        Pass in the successful network to scan
        """
        output = ARPScan().run("192.168.1.0/24")

        self.assertIsInstance(output, list)

    def test_invalid_ip_networks(self):
        """
        Test the input of invalid networks
        """
        # Not an ip network
        not_an_ip = ARPScan().run("ikuadhiduahodauhad")

        # Invalid IP network
        invalid_ip = ARPScan().run("10.0.3.0/24")

        self.assertEqual(not_an_ip, None)
        self.assertEqual(invalid_ip, [])

    def test_successful_ip(self):
        """
        Pass in the successful network to scan
        """
        output = ARPScan().run("192.168.1.254")

        self.assertIsInstance(output, list)

    def test_invalid_ip(self):
        """
        Test an invalid ip that is not on network
        """
        output = ARPScan().run("19.68.1.54")
        self.assertEqual(output, [])


if __name__ == '__main__':
    unittest.main()