import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

# ----------------- Load Dataset -----------------
df = pd.read_csv("kddcup.data_10_percent.csv.gz", compression='gzip', header=None)

# ----------------- Column Names (important) -----------------
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins',
    'logged_in','num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate',
    'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate',
    'dst_host_srv_rerror_rate','label'
]

df.columns = columns

# ----------------- Convert label to Attack/Normal -----------------
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal.' else 1)

# ----------------- Encode categorical -----------------
le = LabelEncoder()

df['protocol_type'] = le.fit_transform(df['protocol_type'])
df['service'] = le.fit_transform(df['service'])
df['flag'] = le.fit_transform(df['flag'])

# ----------------- SELECT SAME FEATURES AS YOUR PROJECT -----------------
features = [
    'duration','src_bytes','dst_bytes',
    'count','same_srv_rate','serror_rate',
    'flag','logged_in'
]

X = df[features]
y = df['label']

# ----------------- Train Test Split -----------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ----------------- Model -----------------
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42,
    class_weight='balanced'
)

model.fit(X_train, y_train)

# ----------------- Evaluation -----------------
y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nReport:\n", classification_report(y_test, y_pred))

# ----------------- Save -----------------
os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/model.pkl")

print("\n Real Dataset Model Ready!")