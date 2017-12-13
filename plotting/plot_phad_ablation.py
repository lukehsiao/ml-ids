"""Plot PHAD feature ablation results."""
import matplotlib
matplotlib.use('Agg')
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

sns.set(style="whitegrid")
fig, ax = plt.subplots(figsize=(6, 4))

data = pd.read_csv("../data/phad_ablation.csv")
data = data.sort_values("f1", ascending=True)

sns.set_color_codes("muted")
sns.barplot(y="f1", x="ablated", data=data, palette=data["color"], ax=ax)
ax.set_xlabel("Ablated Feature")
ax.set_ylabel("F1 Score")
ax.set_ylim((0.00, 0.40))
for item in ax.get_xticklabels():
    item.set_rotation(90)
sns.despine(left=True, bottom=True)
plt.setp(fig.axes)
plt.tight_layout(h_pad=3)
pp = PdfPages("phad_ablation.pdf")
pp.savefig(fig)
pp.close()
plt.close(fig)

fig, ax = plt.subplots(figsize=(6, 4))
data = pd.read_csv("../data/phad_compounding_ablation.csv")

sns.set_color_codes("muted")
sns.barplot(y="f1", x="ablated", data=data, palette=data["color"], ax=ax)
ax.set_xlabel("Additionally Removed Feature (from All to 1)")
ax.set_ylabel("F1 Score")
ax.set_ylim((0.00, 0.40))
for item in ax.get_xticklabels():
    item.set_rotation(90)
sns.despine(left=True, bottom=True)
plt.setp(fig.axes)
plt.tight_layout(h_pad=3)
pp = PdfPages("phad_compounding_ablation.pdf")
pp.savefig(fig)
pp.close()
plt.close(fig)
