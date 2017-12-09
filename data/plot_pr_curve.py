import pandas as pd
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages

data = pd.read_csv("pr_curve.csv")

plot = sns.lmplot(x="recall", y="precision", data=data, fit_reg=False,
                  markers=".")
plot.set(ylim=(0,1))
plot.set(xlim=(0,1))

pp = PdfPages("pr_curve.pdf")
pp.savefig(plot.fig)
pp.close()
