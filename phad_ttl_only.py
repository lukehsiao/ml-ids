#!/usr/bin/env python

"""This code recreates the PHAD-C32 experiments in the original PHAD paper."""
from __future__ import print_function, division
import cPickle as pickle
import csv
from math import log10
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import socket
import struct
from utils import Clusterer
from utils import np_parse_pcap, FEATURES
from utils import tstamp_to_datetime
from check_results import *


def _clusterTraining(trainingData, verbose=False):

    try:
        features = pickle.load(open("data/phad_clusters.pkl", "rb"))
        print("Loading pre-parsed cluster data...", end='')
    except IOError:
        print("Clustering the header fields...", end='')
        features = {key: Clusterer() for key in FEATURES}

        # First column of training data is the timestamp, which we ignore
        for packetHdrs in trainingData[:, 1:]:
            # Iterate over FEATURES so indexes are the correct order
            for i, feature in enumerate(FEATURES):
                if packetHdrs[i] != -1:
                    # NOTE(lwhsiao): Right now we're just doing this all
                    # together. One potential way to parallelize is to
                    # instead update each Clusterer in parallel, providing
                    # a single column of packet headers to each, rather
                    # than processing them all together.
                    features[feature].add(packetHdrs[i])

        pickle.dump(features, open("data/phad_clusters.pkl", "wb"))

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
        allData = np.load(open("data/test_data.npy", "rb"))
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

        np.save(open("data/test_data.npy", "wb"), allData)

    print("Done!")
    return allData


def _parseTrainingData():
    """Parse the week 3 training data."""
    try:
        allData = np.load(open("data/train_data.npy", "rb"))
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
        np.save(open("data/train_data.npy", "wb"), allData)

    print("Done!")
    return allData


def _normalizeScore(score):
    """Normalize score on log scale as done in paper."""
    # NOTE: This function is deprecated. This is the equation used in the
    # original paper, but it doesn't make any sense (results in scores that
    # are not in [0, 1]. Instead, we've moved to the MinMaxScaler from sklearn
    return (0.1 * log10(score) - 0.6)


def _runScoring(clusters, testData):
    """Run attack detection on test data using clusters from train data."""

    try:
        results = np.load(open("data/phad_results.npy", "rb"))
        print("Loading cached results...", end='')
    except IOError:
        print("Running attack detection...", end='')
        # Initialize last anomaly time to 1 sec before time of first packet.
        # The first column of testData is the timestamp.
        lastAnomaly = {key: testData[0][0] - 1 for key in FEATURES}
        nr = {key: (clusters[key].getTotal(), clusters[key].getDistinct()) for
              key in FEATURES}

        scores = np.zeros(testData.shape)
        for packetNum, packet in enumerate(testData):
            packetHdrs = packet[1:]
            timestamp = packet[0]

            # Score each field
            for i, feature in enumerate(FEATURES):
                # If not anomalous, don't score
                if clusters[feature].contains(packetHdrs[i]):
                    continue
                if packet[i] != -1:
                    t = timestamp - lastAnomaly[feature]
                    scores[packetNum][i] = (t * nr[feature][0] /
                                            nr[feature][1])
                    lastAnomaly[feature] = timestamp

        # Zero all but IPv4_ttl (idx = 11)
        scores[:, :11] = 0
        scores[:, 12:] = 0

        # Score the packet and store as last element
        scores[:, -1] = np.sum(scores[:, 0:-1], axis=1)


        # If the total score of the packet is very small, set it to one so
        # that taking the log later doesn't fail.
        scores[:, -1][scores[:, -1] < 1] = 1

        results = np.hstack((testData, scores))
        np.save(open("data/phad_results.npy", "wb"), results)

    print("Done!")

    return results


def _outputToCSV(results, filename, threshold=0.5, feat=None):
    """Classify all attacks with a score above threshold as an attack."""

    outfile = open(filename, "wb")
    writer = csv.writer(outfile)

    # Normalize Scores:
    scaler = MinMaxScaler()
    origScores = results[:, -1].reshape(-1, 1)
    logScores = np.log10(origScores)
    scaler.fit(logScores)
    scaledScores = scaler.transform(logScores)
    for packet, scaledScore in zip(results, scaledScores):
        #  for packet in results:
        datetime = tstamp_to_datetime(packet[0])
        scores = packet[34:]

        if packet[16] != -1:
            destIP = socket.inet_ntoa(struct.pack('!L', packet[16]))
        else:
            destIP = "0.0.0.0"

        mostAnomalous = FEATURES[scores[0:-1].argmax()]
        percentage = scores[0:-1].max() / scores[-1]
        #  score = _normalizeScore(scores[-1])

        if scaledScore >= threshold:
            writer.writerow([datetime[0],
                             datetime[1],
                             destIP,
                             scaledScore[0],
                             #  score,
                             mostAnomalous,
                             percentage])

    outfile.close()
    print("Output results to file!")


def main():
    """Run the PHAD-C32 experiment."""
    trainData = _parseTrainingData()
    # Clustering header data
    clusters = _clusterTraining(trainData)
    del trainData

    testData = _parseTestingData()
    results = _runScoring(clusters, testData)
    #  outfile = open("data/phad_ablation.csv", "wb")
    #  writer = csv.writer(outfile)
    import pdb; pdb.set_trace()
    _outputToCSV(results, "data/phad_results.csv", threshold=0.5, feat=None)
    data = check_results('data/phad_results.csv',
                         'data/master-listfile-condensed.txt',
                         '0.60:0.80:400',
                         False,
                         False)
    print(">>> %s %f" % ("All", max(data['f1s'])))
    #  writer.writerow(["All", max(data['f1s'])])
    #
    #  for feat in xrange(33):
    #      results = _runScoring(clusters, testData)
    #      _outputToCSV(results, "data/phad_results.csv", threshold=0.5, feat=feat)
    #      data = check_results('data/phad_results.csv',
    #                           'data/master-listfile-condensed.txt',
    #                           '0.60:0.80:400',
    #                           False,
    #                           False)
    #      print(">>> %s %f" % (FEATURES[feat], max(data['f1s'])))
    #      writer.writerow([FEATURES[feat], max(data['f1s'])])
    #
    #  outfile.close()


if __name__ == '__main__':
    main()
