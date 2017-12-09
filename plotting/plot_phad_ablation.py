"""Plot PHAD all-but-1 feature ablation results."""
from matplotlib.backends.backend_pdf import PdfPages
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

sns.set(style="whitegrid")
fig, ax = plt.subplots(figsize=(4,6))

data = pd.read_csv("../data/phad_ablation.csv")
data = data.sort_values("f1", ascending=True)

sns.set_color_codes("muted")
sns.barplot(y="ablated", x="f1", data=data, palette=data["color"], ax=ax)
ax.set_ylabel("Ablated Feature")
ax.set_xlabel("F1 Score")
ax.set_xlim((0.23, 0.40))
sns.despine(left=True, bottom=True)
plt.setp(fig.axes)
plt.tight_layout(h_pad=3)
pp = PdfPages("phad_ablation.pdf")
pp.savefig(fig)
pp.close()
