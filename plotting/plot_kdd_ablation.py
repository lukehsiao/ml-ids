"""Plot KDD feature ablation results."""
import matplotlib
matplotlib.use('Agg')
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

sns.set(style="whitegrid")
fig, ax = plt.subplots(figsize=(6, 4))

data = pd.read_csv("../data/kdd_ablation.csv")
data = data.sort_values("f1", ascending=True)

sns.set_color_codes("muted")
sns.barplot(y="f1", x="ablated", data=data, palette=data["color"], ax=ax)
ax.set_xlabel("Feature Used")
ax.set_ylabel("F1 Score")
ax.set_ylim((0.00, 1.00))
for item in ax.get_xticklabels():
    item.set_rotation(90)
sns.despine(left=True, bottom=True)
plt.setp(fig.axes)
plt.tight_layout(h_pad=3)
pp = PdfPages("kdd_ablation.pdf")
pp.savefig(fig)
pp.close()
plt.close(fig)

