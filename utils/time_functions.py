
import sys, os, re
from datetime import datetime

# num seconds to convert from EST to PST
ADJUSTMENT_TIME = 3*3600

def datetime_to_tstamp(date, time, adjust=True):
    """Convert date and time strings into a timestamp matching the pcap files
    Inputs:
      - date string with the format: MM/DD/YYYY
      - time string with the format: HH:MM:SS

    Returns:
      - float timestamp
    """
    date_fmat = r'(?P<month>.{2})/(?P<day>.{2})/(?P<year>.{4})'
    time_fmat = r'(?P<hour>.{2}):(?P<min>.{2}):(?P<sec>.{2})'
    d = re.search(date_fmat, date)
    if (d is None):
        print >> sys.stderr, "ERROR: datetime_to_tstamp: invalid date string: {}".format(date)
        return
    t = re.search(time_fmat, time)
    if (t is None):
        print >> sys.stderr, "ERROR: datetime_to_tstamp: invalid time string: {}".format(time)
        return
    dt = datetime(int(d.group('year')), int(d.group('month')), int(d.group('day')), int(t.group('hour')), int(t.group('min')), int(t.group('sec')))
    if adjust:
        result = float(dt.strftime("%s")) - ADJUSTMENT_TIME
    else:
        result = float(dt.strftime("%s"))
    return result


def tstamp_to_datetime(tstamp):
    """Converts a pcap timestamp to date and time
    Input:
      - float timestamp

    Returns:
      - list where first element is date string: MM/DD/YYYY
      - second element is time string: HH:MM:SS
    """
    result = datetime.fromtimestamp(tstamp + ADJUSTMENT_TIME).strftime('%m/%d/%Y %H:%M:%S')
    return result.split()

def dur_to_sec(dur):
    """Convert duration string with format HH:MM:SS to float
    """
    dur_fmat = r'(?P<hour>.{2}):(?P<min>.{2}):(?P<sec>.{2})'
    d = re.search(dur_fmat, dur)
    if (d is None):
        print >> sys.stderr, "ERROR: dur_to_sec: invalid duration string"
        return
    return float(d.group('hour'))*3600 + float(d.group('min'))*60 + float(d.group('sec'))

"""
First packet times for each day of testing:

start_time_map = {
    '03/29/1999':('08:00:02', 9.22712402005345940589904785156250e+08),
    '03/31/1999':('08:00:09', 9.22885209075160026550292968750000e+08),
    '04/01/1999':('08:00:01', 9.22971601356755018234252929687500e+08),
    '04/02/1999':('08:00:00', 9.23058000588664054870605468750000e+08),
    '04/05/1999':('08:00:02', 9.23313602809497952461242675781250e+08),
    '04/06/1999':('08:00:00', 9.23400000174049019813537597656250e+08),
    '04/07/1999':('08:00:00', 9.23486400744150996208190917968750e+08]),
    '04/08/1999':('08:00:00', 9.23572800784062981605529785156250e+08]),
    '04/09/1999':('08:00:04', 9.23659204991575956344604492187500e+08])
}
"""


