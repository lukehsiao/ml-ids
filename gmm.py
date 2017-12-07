#!/usr/bin/env python
"""Network intrusion detection using a GMM."""
from __future__ import print_function, division
import cPickle as pickle
import csv
import numpy as np
from utils import np_parse_pcap, FEATURES
from utils import tstamp_to_datetime
import socket
import struct
from sklearn.mixture import GaussianMixture
from sklearn import preprocessing


def _parseTrainingData():
    """Parse the week 3 training data."""
    try:
        allData = np.load(open("data/gmm_train_data.npy", "rb"))
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
        allDays = np_parse_pcap(trainingFiles)
        # Create a single matrix of packets x features
        trainData = np.vstack([pkts for (pkts, times) in allDays])
        # Create a single matrix of packets x features
        trainTimes = np.vstack([times for (pkts, times) in allDays])

        allData = np.hstack((trainTimes, trainData))
        np.save(open("data/gmm_train_data.npy", "wb"), allData)

    print("Done!")
    return allData

def _parseTestingData():
    """Parse week 4 and 5 of testing data."""
    try:
        allData = np.load(open("data/gmm_test_data.npy", "rb"))
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

        allDays = np_parse_pcap(testingFiles)
        # Create a single matrix of packets x features
        testData = np.vstack([pkts for (pkts, times) in allDays])
        # Create a single matrix of packets x features
        testTimes = np.vstack([times for (pkts, times) in allDays])
        allData = np.hstack((testTimes, testData))

        np.save(open("data/gmm_test_data.npy", "wb"), allData)

    print("Done!")
    return allData


def _outputToCSV(results, filename, threshold=1e-8):
    """Classify all attacks with a score above threshold as an attack."""

    outfile = open(filename, "wb")
    writer = csv.writer(outfile)

    for packet in results:
        datetime = tstamp_to_datetime(packet[0])

        if packet[16] != -1:
            destIP = socket.inet_ntoa(struct.pack('!L', packet[16]))
        else:
            destIP = "0.0.0.0"

        # Only write the most improbable packets
        if packet[-1] < (1.0 - threshold):
            writer.writerow([datetime[0],
                             datetime[1],
                             destIP,
                             1. - packet[-1]])

    outfile.close()
    print("Output results to file!")


def _score(probs):
    """Produce a score for each entry in probs."""
    scores = np.zeros(probs.shape[0])

    # scores = np.linalg.norm(probs, axis=1)
    scores = np.amax(probs, axis=1)

    return scores


def main():
    """Run the IDS using GMM experiment."""
    week3Data = _parseTrainingData()

    # Scale the training data (ignore the timestamp column)
    scaler = preprocessing.RobustScaler().fit(week3Data[:, 1:])
    X_train = scaler.transform(week3Data[:, 1:])
    del week3Data

    try:
        gmm = pickle.load(open("data/gmm.pkl", "rb"))
        print("Loading pre-trained GMM...")
    except IOError:
        print("Training the Gaussian Mixture...")
        gmm = GaussianMixture(n_components=16,
                              covariance_type='full',
                              #  reg_covar=1,
                              verbose=1,
                              verbose_interval=2).fit(X_train)
        pickle.dump(gmm, open("data/gmm.pkl", "wb"))
    del X_train

    X_orig = _parseTestingData()
    print("Scaling the test data...")
    X_test = scaler.transform(X_orig[:, 1:])

    print("Calculating prosterior probabilies of test data...")
    probs = gmm.predict_proba(X_test)
    del X_test

    scores = _score(probs)
    del probs

    results = np.hstack((X_orig, scores.reshape((scores.shape[0], 1))))

    _outputToCSV(results, "data/gmm_results_max.csv")


if __name__ == '__main__':
    main()

