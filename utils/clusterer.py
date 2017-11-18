class Clusterer:
    """Data structure for clustering continuous data.

    Data structure for use in PHAD-C. Stores a list of ranges or clusters up to
    a maximum of C (32 by default). If C is exceeded during training, then we
    find the two closest ranges and merge them.
    """
    def __init__(self, C=32):
        """Initialize the Clusterer."""
        self.C = C   # Maximum number of clusters
        self.R = 0   # Approximation of distinct values added
        self.N = 0   # Total number of values added
        self.clusters = []

    def add(self, value):
        """Add a new value to the cluster."""
        # Increment total values counter
        self.N += 1

        if self.contains(value):
            return

        # Add item to list and inc distinct value counter
        self.clusters.append([value, value])
        self.clusters.sort()
        self.R += 1

        # Merge clusters if necessary to maintain maximum C
        if len(self.clusters) > self.C:
            # Compute distances between each range (ignoring first wraparound)
            distances = [self.clusters[i][0] - self.clusters[i-1][1]
                         for i in range(len(self.clusters))][1:]
            minIndex = distances.index(min(distances))

            self.clusters[minIndex][1] = self.clusters[minIndex + 1][1]
            self.clusters.remove(self.clusters[minIndex + 1])

    def getDistinct(self):
        """Return the approximation of distinct values seen."""
        return self.R

    def getTotal(self):
        """Return the total number of values added."""
        return self.N

    def getClusters(self):
        """Return the list of ranges."""
        return self.clusters

    def clear(self):
        """Clear the contents of the Clusterer."""
        self.R = 0
        self.N = 0
        self.clusters = []

    def contains(self, value):
        """Check if the value falls into any existing cluster."""
        for low, high in self.clusters:
            if value >= low and value <= high:
                return True

        return False
