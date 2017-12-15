import sys
sys.path.append("..")
from utils import Kdd_Parser

p = Kdd_Parser('kdd_data/kddcup.names', 'kdd_data/training', 'kdd_data/testing', 'binary')
p.save_data('kdd_data/cache')

