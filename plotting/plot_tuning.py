"""Plot Precision-Recall Curve and F1 vs Threshold for PHAD."""
import matplotlib
matplotlib.use('Agg')
from matplotlib.backends.backend_pdf import PdfPages
import pandas as pd
import seaborn as sns


sns.set(font_scale=3.0, style="ticks")
data = pd.read_csv("../data/phad_tuning.csv")

plot = sns.lmplot(x="recall", y="precision", data=data, fit_reg=False,
                  markers=".", scatter_kws={"s": 200}, aspect=2)
plot.set(ylim=(0, 1))
plot.set(xlim=(0, 1))
plot.set(ylabel="Precision")
plot.set(xlabel="Recall")

pp = PdfPages("pr_curve.pdf")
pp.savefig(plot.fig)
pp.close()

plot = sns.lmplot(x="threshold", y="f1", data=data, fit_reg=False,
                   markers=".", scatter_kws={"s": 200}, aspect=2)

plot.set(ylim=(0, 1))
plot.set(xlim=(0.5, 1))
plot.set(ylabel="F1 Score")
plot.set(xlabel="Threshold Value")
pp = PdfPages("f1_curve.pdf")
pp.savefig(plot.fig)
pp.close()

plot = sns.lmplot(x="TotalNumFP", y="recall", data=data,
                  fit_reg=False, markers=".", scatter_kws={"s": 200},
                  aspect=2)

plot.set(ylim=(0, 1))
plot.set(xlim=(0, 200))
plot.set(ylabel=r"Recall")
plot.set(xlabel="Num False Positives")
pp = PdfPages("dfa_curve.pdf")
pp.savefig(plot.fig)
pp.close()
