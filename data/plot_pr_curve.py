import pandas as pd
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages


sns.set(font_scale=3.0, style="ticks")
data = pd.read_csv("pr_curve.csv")

plot = sns.lmplot(x="recall", y="precision", data=data, fit_reg=False,
                  markers=".", scatter_kws={"s": 200}, aspect=2)
plot.set(ylim=(0, 1))
plot.set(xlim=(0, 1))
plot.set(ylabel="Precision")
plot.set(xlabel="Recall")

pp = PdfPages("pr_curve.pdf")
pp.savefig(plot.fig)
pp.close()

data2 = pd.read_csv("../temp.csv")

plot2 = sns.lmplot(x="threshold", y="f1", data=data2, fit_reg=False,
                   markers=".", scatter_kws={"s": 200}, aspect=2)

plot2.set(ylim=(0, 1))
plot2.set(xlim=(0.5, 1))
plot2.set(ylabel="F1 Score")
plot2.set(xlabel="Threshold Value")
pp = PdfPages("f1_curve.pdf")
pp.savefig(plot2.fig)
pp.close()
