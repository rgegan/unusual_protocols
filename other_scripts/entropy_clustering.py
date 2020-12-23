import seaborn as sns
import pandas as pd
import matplotlib as mpl
import os
from matplotlib import cm
from scipy.stats import zscore
from sklearn.preprocessing import MinMaxScaler
from sklearn.cluster import DBSCAN
from sklearn.cluster import OPTICS, cluster_optics_dbscan
from datetime import datetime
from time import mktime

#set the protocol number
protocol_number = 6

# Read the file and process the log first
file1 = open('protocol_totals.log', 'r') 
Lines = file1.readlines() 
  
count = 0
# Strips the newline character
log_file = open('processed_log.txt', 'w') 
log_file.writelines("time entropy")
log_file.writelines("\n")

for line in Lines: 
    split_line = line.split()
    if split_line[1] == 'Statistics':
        log_file.writelines(split_line[0])
        log_file.writelines(" ")
        log_file.writelines(split_line[6])
        log_file.writelines("\n")
log_file.close()


processed_csv = pd.read_csv('processed_log.txt', delimiter=r"\s+")#sns.load_dataset('titanic')
processed_csv =  pd.read_csv('processed_log.txt', delimiter=r"\s+")
processed_csv = processed_csv.copy()
processed_csv = processed_csv.dropna()


timeAndCount = processed_csv[["time", "entropy"]]

# define clustering parameters here
outlier_detection = DBSCAN(
  eps = 1000,
  metric="euclidean",
  min_samples = 10,
  n_jobs = -1)
clusters = outlier_detection.fit_predict(timeAndCount)

#print(clusters)

cmap = cm.get_cmap('Accent')

p=timeAndCount.plot.scatter(
  x = "time",
  y = "entropy",
  c = clusters,
  cmap = cmap,
  colorbar = False
)

mpl.pyplot.ylim(ymin=0)
mpl.pyplot.ylim(ymax=1)
mpl.pyplot.show(p)

if os.path.exists("processed_log.txt"):
  os.remove("processed_log.txt")

