
import sys, os, re
import numpy as np
from kdd_categories import category_str2int, category_int2str

class Kdd_Schema(object):
    def __init__(self, schema_file, label_type):
        """
        Inputs:
            - schema_file : the file with the schema description
            - label_type : int, binary, or one-hot encoded
        """

        self.label_type = label_type

        # maps the index within the line to : (feature_name, feature_type)
        #   where feature_type is either 'continuous' or 'symbolic'
        self.schema_key = {}

        # a list of all possible string labels
        self.labels = []

        # maps symbolic features to possible values 
        self.symbolic_features = {}

        with open(schema_file) as f:
            line_num = 0
            for line in f:
                line = line.replace('.','')
                if line_num == 0:
                    self.labels = [s.strip() for s in line.split(',')]
                else:
                    [feature_name, feature_type] = line.split(': ')
                    feature_name = feature_name.strip()
                    feature_type = feature_type.strip()
                    self.schema_key[line_num-1] = (feature_name, feature_type)
                    if feature_type == 'symbolic':
                        self.symbolic_features[feature_name] = []
                line_num += 1

        self.num_features = len(self.schema_key.keys())
        self.num_classes = len(category_int2str.keys())

        self.feature_list = [self.schema_key[i][0] for i in range(self.num_features)]

    def convert_line(self, line):
        """Converts a line from the training or test data files into a numpy array for the
           design matrix and a label value
        """
        line = line.split(',')
        if len(line)-1 < self.num_features:
            #print >> sys.stderr, "WARNING: invalid line: {}".format(line)
            return None, None
        str_label = line[-1].replace('.','')
        label = self.label_str2num(str_label)
        line = line[0:-1]
        example = np.zeros((1, len(line)))
        for item, index in zip(line, range(len(line))):
            example[0,index] = self.feature_str2num(item, index)
        return example, label


    def label_str2num(self, str_label):
        """Convert string label into numerical label (either binary or one-hot)
        """
        if self.label_type == 'binary':
            return 0 if str_label == 'normal' else 1
        elif self.label_type == 'int':
            return category_str2int[str_label]
        elif self.label_type == 'one-hot':
            label = np.zeros((1, self.num_classes))
            index = category_str2int[str_label]
            label[0, index] = 1
            return label

    def label_num2str(self, num_label):
        """Convert numerical label into string
        """
        if self.label_type == 'binary':
            return 'attack' if num_label == 1 else 'normal'
        elif self.label_type == 'int':
            return category_int2str[num_label]
        elif self.label_type == 'one-hot':
            # Assume num_label.shape = (1, num_classes)
            index = num_label.tolist()[0].index(1)
            try:
                label_str = category_int2str[index]
            except KeyError as e:
                print >> sys.stderr, "ERROR: Invalid one-hot label: {}".format(num_label)
                sys.exit(1)
            return label_str

    def feature_str2num(self, str_val, index):
        """Given the string value and index within the line, convert the feature into a numerical value
        """
        (feature_name, feature_type) = self.schema_key[index]
        if feature_type == 'symbolic':
            try:
                feat_val = float(self.symbolic_features[feature_name].index(str_val))
            except ValueError as e:
                self.symbolic_features[feature_name].append(str_val)
                feat_val = float(self.symbolic_features[feature_name].index(str_val))
        else:
            feat_val = float(str_val)
        return feat_val

    def feature_num2str(self, num_val, index):
        """Given the numerical value and index within the list, convert the feature into a string
        """
        (feature_name, feature_type) = self.schema_key[index]
        if feature_type == 'symbolic':
            try:
                feat_str = self.symbolic_features[feature_name][num_val]
            except IndexError as e:
                print >> sys.stderr, "ERROR: feature_num2str: invalid feature value for symbolic symbol: {}".format(num_val)
                sys.exit(1)
        else:
            feat_str = str(num_val)
        return feat_str


class Kdd_Parser(object):
    def __init__(self, schema_file, train_file, test_file, label_type='int'):
        self.schema = Kdd_Schema(schema_file, label_type)
        self.label_type = label_type

        self.train_data, self.train_labels = self.read_data(train_file)
        self.test_data, self.test_labels = self.read_data(test_file)

    def read_data(self, filename):
        try:
            contents = open(filename).read()
        except IOError as e:
            print >> sys.stderr, "ERROR: cannot open file {}".format(filename)
            sys.exit(1)

        all_lines = contents.split('\n')
        num_examples = len(all_lines) - 1 # last line is empty
        num_features = self.schema.num_features
        data = np.zeros((num_examples, num_features))
        if self.label_type == 'binary' or self.label_type == 'int':
            labels = np.zeros((num_examples, 1))
        elif self.label_type == 'one-hot':
            labels = np.zeros((num_examples, self.schema.num_classes))
        lineNo = 0
        for line in all_lines:
            example, label = self.schema.convert_line(line)
            if example is not None:
                data[[lineNo], :] = example
                labels[[lineNo], :] = label
                lineNo += 1
        return data, labels

    def save_data(self, outDir):
        """Save the training and test data to outDir
        """
        # create outDir if it does not exist
        if not os.path.exists(outDir):
            os.makedirs(outDir)

        train_data_file = os.path.join(outDir, 'train_data')
        np.save(train_data_file, self.train_data)

        train_labels_file = os.path.join(outDir, 'train_labels_{}'.format(self.label_type))
        np.save(train_labels_file, self.train_labels)

        test_data_file = os.path.join(outDir, 'test_data')
        np.save(test_data_file, self.test_data)

        test_labels_file = os.path.join(outDir, 'test_labels_{}'.format(self.label_type))
        np.save(test_labels_file, self.test_labels)






