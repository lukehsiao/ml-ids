import sys, os, json
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import f1_score
import matplotlib.pyplot as plt
from utils import Kdd_Schema
from multiprocessing import Pool, cpu_count

class KNN_Model(object):
    def __init__(self, n_neighbors):
        self.n_neighbors = n_neighbors
        self.neigh = KNeighborsClassifier(n_neighbors=n_neighbors)

    def train(self, train_data, train_labels):
        self.neigh.fit(train_data, train_labels)

    def test(self, test_data):
        pred_labels = self.neigh.predict(test_data)
        return pred_labels

class Ablation_Exp(object):
    """Performs an ablation experiment where we start with all features and remove
       one at a time. Plot the F1 Score.
    """
    def __init__(self, outDir, schema_file):
        self.outDir = outDir
        schema = Kdd_Schema(schema_file, 'binary')
        self.feature_list = schema.feature_list

    def run_exp(self, train_data_file, train_labels_file, test_data_file, test_labels_file):
        train_data = np.load(train_data_file)
        test_data = np.load(test_data_file)
        num_features = train_data.shape[1]

        del train_data
        del test_data

        feature_to_try = range(num_features)
        params_list = zip([train_data_file]*num_features, [train_labels_file]*num_features, [test_data_file]*num_features, [test_labels_file]*num_features, feature_to_try)

#        f1_scores = map(calc_f1_score, params_list)
        p = Pool(cpu_count())
        f1_scores = p.map(calc_f1_score, params_list)

        self.record_f1_scores(f1_scores)


    def record_f1_scores(self, f1_scores):
        filename = os.path.join(self.outDir, 'kdd_ablation.csv')
        with open(filename, 'w') as f:
            f.write('color,ablated,f1\n')
            for feat, score in zip(self.feature_list, f1_scores):
                f.write('b,{},{}\n'.format(feat, score))

# This runs in parallel
def calc_f1_score(in_tuple):
    train_data_file = in_tuple[0]
    train_labels_file = in_tuple[1]
    test_data_file = in_tuple[2]
    test_labels_file = in_tuple[3]
    feat_to_try = in_tuple[4]

    train_data = np.load(train_data_file)
    train_labels = np.load(train_labels_file)
    test_data = np.load(test_data_file)
    test_labels = np.load(test_labels_file)

    #### prune data
    train_data = train_data[:, [feat_to_try]]
    train_labels = train_labels[:, 0]
    test_data = test_data[:, [feat_to_try]]
    test_labels = test_labels[:, 0]
    ####

    knn = KNN_Model(1)
    knn.train(train_data, train_labels)
    pred_labels = knn.test(test_data)

    score = f1_score(test_labels, pred_labels, pos_label=0)
    print 'Finished features: {}:end'.format(feat_to_try)
    return score

def main():
    exp = Ablation_Exp('data', 'data/kdd_data/kddcup.names')
    exp.run_exp('data/kdd_data/cache/train_data.npy', 'data/kdd_data/cache/train_labels_binary.npy', 'data/kdd_data/cache/test_data.npy', 'data/kdd_data/cache/test_labels_binary.npy')

if __name__ == '__main__':
    main()


