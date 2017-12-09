
import sys, os, json
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import f1_score
import matplotlib.pyplot as plt
from kdd_parser import Kdd_Schema
from multiprocessing import Pool, cpu_count

class KNN_Model(object):
    def __init__(self, n_neighbors):
        self.n_neighbors = n_neighbors
        self.neigh = KNeighborsClassifier(n_neighbors=n_neighbors)

    def train(self, train_data, train_labels):
        self.neigh.fit(train_data, train_labels)
#        params = self.neigh.get_params()
#        with open(os.path.join(self.outDir, 'params.json'), 'w') as f:
#            json.dump(params, f)

    def test(self, test_data):
        pred_labels = self.neigh.predict(test_data)
        return pred_labels

#    def write_labels(self, labels, filename):
#        with open(filename, 'w') as f:
#            for l in labels:
#                f.write('{}\n'.format(int(l)))

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

        #### initial testing
#        self.train_examples = np.random.randint(0, train_data.shape[0], 10000)
#        self.test_examples = np.random.randint(0, test_data.shape[0], 5000)
        ####

        del train_data
        del test_data
        features_to_use = range(num_features)
        params_list = zip([train_data_file]*num_features, [train_labels_file]*num_features, [test_data_file]*num_features, [test_labels_file]*num_features, features_to_use)

#        f1_scores = map(calc_f1_score, params_list)
        p = Pool(cpu_count())
        f1_scores = p.map(calc_f1_score, params_list)

        self.record_f1_scores(f1_scores)
#        self.plot_f1_scores(f1_scores, self.feature_list)
#        plt.show()

    def record_f1_scores(self, f1_scores):
        data = {}
        data['f1_scores'] = f1_scores
        data['feature_list'] = self.feature_list
        with open(os.path.join(self.outDir, 'f1_scores.json'), 'w') as f:
            json.dump(data, f)

    def plot_f1_scores(self, f1_scores, xlabels):
        plt.figure()
        xdata = range(len(f1_scores))
        plt.bar(xdata, f1_scores, align='center', alpha=0.5)
        plt.xticks(xdata, xlabels, rotation='vertical')
        plt.subplots_adjust(bottom=0.35)
        plt.title('Ablative Analysis')
        plt.ylabel('F1 Score')

# This runs in parallel
def calc_f1_score(in_tuple):
    assert(len(in_tuple) == 5)
    train_data_file = in_tuple[0]
    train_labels_file = in_tuple[1]
    test_data_file = in_tuple[2]
    test_labels_file = in_tuple[3]
    feat = in_tuple[4]

    train_data = np.load(train_data_file)
    train_labels = np.load(train_labels_file)
    test_data = np.load(test_data_file)
    test_labels = np.load(test_labels_file)

    #### prune data
    train_data = np.delete(train_data, feat, axis=1)
    train_labels = train_labels[:, 0]
    test_data = np.delete(test_data, feat, axis=1)
    test_labels = test_labels[:, 0]
    ####

    knn = KNN_Model(1)
    knn.train(train_data, train_labels)
    pred_labels = knn.test(test_data)

    score = f1_score(test_labels, pred_labels)
    print 'Finished features: {}:end'.format(feat)
    return score


def main():
    exp = Ablation_Exp('kdd_output', 'kdd_data/schema.txt')
#    exp.run_exp('kdd_data/cache/train_data.npy', 'kdd_data/cache/train_labels_binary.npy', 'kdd_data/cache/test_data.npy', 'kdd_data/cache/test_labels_binary.npy')

    with open('kdd_output/f1_scores_ablative_single.json') as f:
        data = json.load(f)
    exp.plot_f1_scores(data['f1_scores'], data['feature_list'])
    plt.show()

if __name__ == '__main__':
    main()


