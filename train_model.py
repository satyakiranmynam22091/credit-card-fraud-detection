print("🚀 Training Started")

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, classification_report
import joblib

# Load dataset
data = pd.read_csv("creditcard.csv")
print("✅ Dataset Loaded")
print("Shape:", data.shape)

# Features & Target
X = data.drop("Class", axis=1)
y = data["Class"]

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Faster solver
model = LogisticRegression(max_iter=500, class_weight="balanced", solver="liblinear")

print("⏳ Training Model...")
model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Evaluation
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred))
print("Recall:", recall_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "fraud_model.pkl")

print("\n✅ Model saved as fraud_model.pkl")