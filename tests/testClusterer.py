import unittest
from utils import Clusterer

class TestClusterer(unittest.TestCase):

    def test_basic(self):
        C = Clusterer()
        C.add(10)
        self.assertEqual(1, C.getTotal())
        self.assertEqual(2, C.getTotal())


if __name__ == '__main__':
    unittest.main()
