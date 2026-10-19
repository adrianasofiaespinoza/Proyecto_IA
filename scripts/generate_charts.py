from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
CSV = ROOT / "results" / "results.csv"
OUT = ROOT / "reports"
OUT.mkdir(exist_ok=True)

df = pd.read_csv(CSV)

required = {
    "vuln_id", "claimed_success", "confidence",
    "A", "F", "S", "V", "FA",
    "generation_status", "eval_status"
}
missing = required - set(df.columns)
if missing:
    raise ValueError(f"Faltan columnas en results.csv: {sorted(missing)}")

# Solo se incluyen evaluaciones completas con generación correcta.
df = df[
    df["generation_status"].eq("ok")
    & df["eval_status"].eq("complete")
].copy()

# Evitar contar como fallos las filas sin evaluación verificable.
for col in ["claimed_success", "confidence", "A", "F", "S"]:
    df[col] = pd.to_numeric(df[col], errors="coerce")

df = df.dropna(
    subset=["claimed_success", "A", "F", "S"]
).copy()

if df.empty:
    raise ValueError("No hay evaluaciones completas utilizables.")

# Recalcular las métricas a partir de los criterios de evaluación.
df["V"] = df["A"] * df["F"] * df["S"]
df["FA"] = df["claimed_success"] * (1 - df["V"])

N = len(df)
sum_V = int(df["V"].sum())
sum_C = int(df["claimed_success"].sum())
sum_FA = int(df["FA"].sum())

VRR = sum_V / N
FAR = sum_FA / sum_C if sum_C else float("nan")

print(f"Evaluaciones completas: {N}")
print(f"Reparaciones verificadas: {sum_V}")
print(f"Afirmaciones de éxito: {sum_C}")
print(f"Falsas seguridades: {sum_FA}")
print(f"VRR: {VRR:.1%}")
print(f"FAR: {FAR:.1%}" if sum_C else "FAR: indefinida")

df.to_csv(OUT / "results_analyzed.csv", index=False)

# Gráfica 1: métricas principales.
fig, ax = plt.subplots(figsize=(8, 5))
labels = ["VRR", "FAR"]
values = [VRR * 100, FAR * 100 if sum_C else 0]
bars = ax.bar(labels, values)
ax.set_ylim(0, 110)
ax.set_ylabel("Porcentaje (%)")
ax.set_title("Resultados de reparación y falsa seguridad")
ax.bar_label(bars, labels=[f"{v:.1f}%" for v in values], padding=4)
ax.grid(axis="y", alpha=0.25)
fig.tight_layout()
fig.savefig(OUT / "01_metricas.png", dpi=180)
plt.close(fig)

# Gráfica 2: matriz de confusión.
# Filas = afirmación del modelo C; columnas = resultado verificado V.
# Orden en ambos ejes: 0, 1.
matrix = [[0, 0], [0, 0]]
for _, row in df.iterrows():
    c = int(row["claimed_success"])
    v = int(row["V"])
    matrix[c][v] += 1

fig, ax = plt.subplots(figsize=(6, 5))
im = ax.imshow(matrix, aspect="equal")
ax.set_xticks([0, 1], labels=["V = 0\nNo verificada", "V = 1\nVerificada"])
ax.set_yticks([0, 1], labels=["C = 0\nNo afirma éxito", "C = 1\nAfirma éxito"])
ax.set_xlabel("Resultado de la evaluación")
ax.set_ylabel("Afirmación del modelo")
ax.set_title("Matriz de confusión: afirmación vs. verificación")

for i in range(2):
    for j in range(2):
        ax.text(j, i, str(matrix[i][j]),
                ha="center", va="center", fontsize=16)

fig.colorbar(im, ax=ax, label="Número de casos")
fig.tight_layout()
fig.savefig(OUT / "02_matriz_confusion.png", dpi=180)
plt.close(fig)

# Gráfica 3: criterios por vulnerabilidad.
plot_df = df.set_index("vuln_id")[["A", "F", "S", "V"]]
ax = plot_df.plot(kind="bar", figsize=(11, 6), ylim=(0, 1.15))
ax.set_title("Evaluación individual de cada vulnerabilidad")
ax.set_xlabel("Identificador de vulnerabilidad")
ax.set_ylabel("Resultado (0 = falla, 1 = pasa)")
ax.legend(["A: parche aplicado", "F: pruebas funcionales",
           "S: pruebas de seguridad", "V: reparación verificada"])
ax.tick_params(axis="x", rotation=25)
ax.grid(axis="y", alpha=0.25)
plt.tight_layout()
plt.savefig(OUT / "03_resultados_por_caso.png", dpi=180)
plt.close()

# Gráfica 4: confianza declarada y resultado verificado.
conf_df = df.dropna(subset=["confidence"]).sort_values("confidence")
fig, ax = plt.subplots(figsize=(9, 5))
ax.scatter(conf_df["confidence"], conf_df["V"], s=75)
ax.set_xlim(0, 1)
ax.set_ylim(-0.15, 1.15)
ax.set_yticks([0, 1], labels=["No verificada", "Verificada"])
ax.set_xlabel("Confianza declarada por el modelo")
ax.set_ylabel("Resultado de verificación")
ax.set_title("Confianza declarada frente a reparación verificada")
ax.grid(alpha=0.25)
fig.tight_layout()
fig.savefig(OUT / "04_confianza_vs_resultado.png", dpi=180)
plt.close(fig)

print(f"\nGráficas guardadas en: {OUT}")
for path in sorted(OUT.glob("*.png")):
    print(f"  {path.relative_to(ROOT)}")
