#! /usr/bin/python
"""This code recreates the PHAD-C32 experiments in the original PHAD paper."""
from __future__ import print_function
import cPickle as pickle
import csv
from math import log10
import numpy as np
import socket
import struct
import time
from utils import Clusterer
from utils.parser import np_parse_pcap, FEATURES


def _clusterTraining(trainingDays, verbose=False):

    try:
        features = pickle.load(open("data/clusters.p", "rb"))
        print("Loading pre-parsed cluster data...", end='')
    except IOError:
        print("Clustering the header fields...", end='')
        features = {key: Clusterer() for key in FEATURES}

        for day in trainingDays:
            for packetHdrs in day[0]:
                # Iterate over FEATURES so indexes are the correct order
                for i, feature in enumerate(FEATURES):
                    if packetHdrs[i] != -1:
                        # NOTE(lwhsiao): Right now we're just doing this all
                        # together. One potential way to parallelize is to
                        # instead update each Clusterer in parallel, providing
                        # a single column of packet headers to each, rather
                        # than processing them all together.
                        features[feature].add(packetHdrs[i])

        pickle.dump(features, open("data/clusters.p", "wb"))

    print("Done!")

    if verbose:
        model = {}
        for feature in features:
            model[feature] = (features[feature].getDistinct(),
                              features[feature].getTotal())
        print(model)

    return features


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
        testData = np_parse_pcap(testingFiles)

        np.save(open("data/test_data.npy", "wb"), testData)

    print("Done!")
    return testData


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
        week3Data = np_parse_pcap(trainingFiles)

        np.save(open("data/week3_data.npy", "wb"), week3Data)

    print("Done!")
    return week3Data


def _normalizeScore(score):
    """Normalize score on log scale as done in paper."""
    return (0.1 * log10(score) - 0.6)


def _runScoring(clusters, testData):
    """Run attack detection on test data using clusters from train data."""

    try:
        results = np.load(open("data/results.npy", "rb"))
        print("Loading cached results...", end='')
    except IOError:
        print("Running attack detection...", end='')
        results = []

        # Initialize last anomaly time to 1 sec before time of first packet
        lastAnomaly = {key: testData[0][1][1] - 1 for key in FEATURES}
        nr = {key: clusters[key].getTotal()/clusters[key].getDistinct() for
              key in FEATURES}

        for day in testData:
            dayScores = np.zeros((day[0].shape[0], day[0].shape[1] + 1))
            # Create array of field and packet scores for each packet
            for packet, timestamp, scores in zip(day[0], day[1], dayScores):
                # Score each field
                for i, feature in enumerate(FEATURES):
                    t = timestamp - lastAnomaly[feature]
                    if packet[i] != -1:
                        scores[i] = t * nr[feature]

                        # If anomalous, reset t
                        if not clusters[feature].contains(packet[i]):
                            lastAnomaly[feature] = timestamp

                # Score the packet and store as last element
                scores[-1] = _normalizeScore(np.sum(scores))

            results.append((day[0], day[1], dayScores))

        np.save(open("data/results.npy", "wb"), results)

    print("Done!")

    return results


def _outputToCSV(results, filename, threshold=0.5):
    """Classify all attacks with a score above threshold as an attack."""

    outfile = open(filename, "wb")
    writer = csv.writer(outfile)

    for day in results:
        for packet, timestamp, scores in zip(day[0], day[1], day[2]):
            if packet[15] != -1:
                datetime = time.strftime('%Y-%m-%d %H:%M:%S',
                                         time.localtime(timestamp))
                destIP = socket.inet_ntoa(struct.pack('!L', packet[15]))
                score = scores[-1]
                # Most anomalous?
                if score >= threshold:
                    writer.writerow([datetime, destIP, score])

    outfile.close()
    print("Output results to file!")


def main():
    """Run the PHAD-C32 experiment."""
    week3Data = _parseTrainingData()
    testData = _parseTestingData()

    # Clustering header data
    clusters = _clusterTraining(week3Data)
    results = _runScoring(clusters, testData)
    #  results = _runScoring(None, None)
    _outputToCSV(results, "data/results.csv", threshold=0.5)


if __name__ == '__main__':
    main()
