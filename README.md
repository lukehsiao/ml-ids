# Machine-learning based intrusion detection

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

## Setting Up the Environment

Update `settings.sh` so that `ML_IDS_DIR` points to the installation location
of the repository. And `SCAPY_PATH` points to the installation location of
python scapy.

Add the following line to your `~/.bashrc` file (modified so that it points
to your modified settings file):

```
source ~/classes/cs229/ml-ids/settings.sh
``` 


