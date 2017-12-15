# Machine-learning based intrusion detection
[![Build Status](https://travis-ci.org/lukehsiao/ml-ids.svg?branch=master)](https://travis-ci.org/lukehsiao/ml-ids)

## Downloading the Datasets

### 1999 DARPA Dataset
Download the [1999 DARPA IDS Dataset]() by running

```
cd data
./download_data.sh
```
This takes about 20 minutes (depending on your internet connection) and
downloads the inside and outside TCPDUMP files from the dataset (~18GB)
organized into training and test sets..


### 1999 DARPA Evaluation Labels
A description of how evaluation is performed for the DARPA dataset, as well as
ground truth files can be found on the [DARPA Dataset
Documentation](https://www.ll.mit.edu/ideval/docs/index.html) page.

## Setting Up the Environment

First, install the python package dependencies by running

```
pip install -r requirements.txt
```

Update `settings.sh` so that `ML_IDS_DIR` points to the installation location
of the repository. And `SCAPY_PATH` points to the installation location of
python scapy.

Add the following line to your `~/.bashrc` file (modified so that it points
to your modified settings file):

```
source ~/classes/cs229/ml-ids/settings.sh
```

## Experiment Files
Our various experiments are organized as Python files in the root of the
repository. Each of the experiments is explained below.

- `gmm.py` - Mixture of Gaussian experiment
  - This experiment uses a stationary mixture of Gaussian model by leveraging
    the sklearn library.
- `phad-c32.py`
  - Our Python implementation of the PHAD-C32 algorithm described in the
    [original
    paper](https://dspace-test.lib.fit.edu/bitstream/handle/11141/94/cs-2001-04.pdf?sequence=1&isAllowed=y)
- `phad_feat_all_but_one.py`
  - A feature ablation experiment for the PHAD algorithm which iteratively
    tests all features except for one.
- `phad_ttl_only.py`
  - A simplified version of PHAD with only uses the `IPv4_ttl` packet field as
    a feature.
- `kdd_knn.py`
  - A K-nearest neighbor model and feature ablation experiment for the KDD
    dataset using the KDD features which iteratively tests a single feature at
    a time.

## Checking Results
`check_results.py` is a simple script used for checking the results of each
experiment.

```
usage: check_results.py [-h] [--thresh THRESH] [--plot] [--table TABLE]
                        results_file attacks_file

positional arguments:
  results_file     the results.csv file
  attacks_file     the actual attacks file

optional arguments:
  -h, --help       show this help message and exit
  --thresh THRESH  range of thresholds to try. Format: start:stop:num_points,
                   default: 0.5:0.5:1
  --plot           make plots
  --table TABLE    make table using the specified threshold
```

## Generating Plots
The plots we used in the poster and paper were generated using the scripts in
`plotting/`.

## Running Tests
To run tests locally, run

```
python -m unittest discover
```

from the root folder of the repository.
