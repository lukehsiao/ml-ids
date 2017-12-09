import pandas as pd
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages

data = pd.read_csv("pr_curve.csv")

plot = sns.lmplot(x="recall", y="precision", data=data, fit_reg=False,
                  markers=".")

pp = PdfPages("pr_curve.pdf")
pp.savefig(plot.fig)
pp.close()
