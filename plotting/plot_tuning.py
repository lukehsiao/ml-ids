"""Plot Precision-Recall Curve and F1 vs Threshold for PHAD."""
import matplotlib
matplotlib.use('Agg')
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


sns.set(font_scale=2.0, style="whitegrid")
data = pd.read_csv("../data/phad_tuning.csv")
DOT_SIZE = 75

data["tp"] = data.apply(lambda row: row.attacksdetected / 100 * 201, axis=1)
data["recall"] = data.apply(lambda row: row.attacksdetected / 100, axis=1)
data["prec"] = data.apply(lambda row: row.tp / (row.tp + row.TotalNumFP), axis=1)
data["f1"] = data.apply(lambda row: (2 * (row.recall * row.prec) /
                                     (row.recall + row.prec)), axis=1)

plot = sns.lmplot(x="recall", y="prec", data=data, fit_reg=False,
                  markers=".", scatter_kws={"s": DOT_SIZE}, aspect=2)
plot.set(ylim=(0, 1))
plot.set(xlim=(0, 1))
plot.set(ylabel="Precision")
plot.set(xlabel="Recall")

pp = PdfPages("pr_curve.pdf")
pp.savefig(plot.fig)
pp.close()

plot = sns.lmplot(x="threshold", y="f1", data=data, fit_reg=False,
                   markers=".", scatter_kws={"s": DOT_SIZE}, aspect=2)

plot.set(ylim=(0, 1))
plot.set(xlim=(0.5, 1))
plot.set(ylabel="F1 Score")
plot.set(xlabel="Threshold Value")
pp = PdfPages("f1_curve.pdf")
pp.savefig(plot.fig)
pp.close()

plot = sns.lmplot(x="TotalNumFP", y="recall", data=data,
                  fit_reg=False, markers=".", scatter_kws={"s": DOT_SIZE},
                  aspect=2)

plot.set(ylim=(0, 1))
plot.set(xlim=(0, 150))
plot.set(ylabel=r"Recall")
plot.set(xlabel="Num False Positives")
plt.axvline(x=100, color='r')
pp = PdfPages("dfa_curve.pdf")
pp.savefig(plot.fig)
pp.close()
