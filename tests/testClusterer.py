import unittest
from utils import Clusterer


class TestClusterer(unittest.TestCase):

    def test_basic(self):
        C = Clusterer()
        C.add(10)
        self.assertEqual(1, C.getTotal())

    def test_merge(self):
        C = Clusterer(C=2)
        C.add(1)
        C.add(2)
        self.assertEqual(2, C.getTotal())
        C.add(8)
        self.assertEqual(3, C.getTotal())
        self.assertEqual(3, C.getDistinct())
        self.assertEqual([[1, 2], [8, 8]], C.getClusters())

        C.add(3)
        self.assertEqual([[1, 3], [8, 8]], C.getClusters())

        C.add(2)
        self.assertEqual([[1, 3], [8, 8]], C.getClusters())
        self.assertEqual(5, C.getTotal())
        self.assertEqual(4, C.getDistinct())

        C.add(9)
        self.assertEqual([[1, 3], [8, 9]], C.getClusters())
        self.assertEqual(6, C.getTotal())
        self.assertEqual(5, C.getDistinct())

        C.add(100)
        self.assertEqual([[1, 9], [100, 100]], C.getClusters())
        self.assertEqual(7, C.getTotal())
        self.assertEqual(6, C.getDistinct())

        C.add(7)
        self.assertEqual([[1, 9], [100, 100]], C.getClusters())
        self.assertEqual(8, C.getTotal())
        self.assertEqual(6, C.getDistinct())

    def test_contains(self):
        C = Clusterer(C=2)
        C.add(1)
        C.add(2)
        C.add(8)
        C.add(3)
        C.add(2)
        C.add(9)
        C.add(100)
        C.add(7)

        self.assertTrue(C.contains(6))
        self.assertFalse(C.contains(10))


if __name__ == '__main__':
    unittest.main()
