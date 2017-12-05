#!/usr/bin/env python
"""Network intrusion detection using a GMM."""
from __future__ import print_function, division
import numpy as np
from utils import np_parse_pcap, FEATURES
from sklearn.mixture import GaussianMixture


def _parseTrainingData():
    """Parse the week 3 training data."""
    try:
        week3Data = np.load(open("data/week3_data.npy", "rb"))
        print("Loading pre-parsed training data...", end='')
    except IOError:
        print("Parsing the training data...", end='')
        # Parse the Training Data
        trainingFiles = [
            "data/training/week3_monday_inside",
            "data/training/week3_monday_extra_inside",
            "data/training/week3_tuesday_inside",
            "data/training/week3_tuesday_extra_inside",
            "data/training/week3_wednesday_inside",
            "data/training/week3_wednesday_extra_inside",
            "data/training/week3_thursday_inside",
            "data/training/week3_friday_inside",
        ]
        # Create a single matrix of packets x features
        week3Data = np.vstack([pkts for (pkts, times) in
                               np_parse_pcap(trainingFiles)])

        np.save(open("data/week3_data.npy", "wb"), week3Data)

    print("Done!")
    return week3Data

def _parseTestingData():
    """Parse week 4 and 5 of testing data."""
    try:
        testData = np.load(open("data/test_data.npy", "rb"))
        print("Loading pre-parsed training data...", end='')
    except IOError:
        print("Parsing the testing data...", end='')
        # Parse the Training Data
        testingFiles = [
            "data/testing/week4_monday_inside",
            #  "data/testing/week4_tuesday_inside",  <-- doesn't exist
            "data/testing/week4_wednesday_inside",
            "data/testing/week4_thursday_inside",
            "data/testing/week4_friday_inside",
            "data/testing/week5_monday_inside",
            "data/testing/week5_tuesday_inside",
            "data/testing/week5_wednesday_inside",
            "data/testing/week5_thursday_inside",
            "data/testing/week5_friday_inside",
        ]
        # Create a single matrix of packets x features
        testData = np.vstack([pkts for (pkts, times) in
                              np_parse_pcap(testingFiles)])

        np.save(open("data/test_data.npy", "wb"), testData)

    print("Done!")
    return testData

def main():
    """Run the IDS using GMM experiment."""
    week3Data = _parseTrainingData()
    #  testData = _parseTestingData()

    # Normalize the test data


    print("Training the Gaussian Mixture...")
    gmm = GaussianMixture(n_components=4,
                          covariance_type='full',
                          reg_covar=1,
                          verbose=1,
                          verbose_interval=2).fit(week3Data)
    # Free up some memory after we've trained
    del week3Data

    import pdb; pdb.set_trace()

if __name__ == '__main__':
    main()

