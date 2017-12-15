
from kdd_parser import *

p = Kdd_Parser('kddcup.names', 'kdd_data/training/kddcup.data_10_percent', 'kdd_data/testing/corrected', 'binary')
p.save_data('kdd_data/cache')

