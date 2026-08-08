from flask import Flask, render_template, request
import pandas as pd
import mysql.connector
import os
import joblib

model = joblib.load('model/model.pkl')

#flask app
app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# mysql connection
def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

# blacklist
def is_blocked(ip):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM blacklist WHERE ip_address = %s", (ip,))
    result = cursor.fetchone()

    cursor.close()
    conn.close()

    return result is not None


def block_ip(ip, reason):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO blacklist (ip_address, reason) VALUES (%s, %s)",
        (ip, reason)
    )

    conn.commit()
    cursor.close()
    conn.close()


#routes
@app.route('/')
def login():
    return render_template("login.html")


@app.route('/home')
def home():
    return render_template("home.html")


@app.route('/dashboard')
def dashboard():
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM predictions")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM predictions WHERE result='Attack'")
    attacks = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM predictions WHERE result='Normal'")
    normal = cursor.fetchone()[0]

    cursor.execute("""
        SELECT duration, src_bytes, result, NOW()
        FROM predictions
        ORDER BY id DESC
        LIMIT 5
    """)
    logs = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        attacks=attacks,
        normal=normal,
        logs=logs
    )


# predict route
@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if request.method == 'GET':
        return render_template("predict.html")

    try:
        ip = request.remote_addr  # Get user IP

       
        if is_blocked(ip):
            return "Access Denied: Your IP is blocked due to suspicious activity."

        data = request.form

        duration = float(data['duration'])
        src_bytes = float(data['src_bytes'])
        dst_bytes = float(data['dst_bytes'])
        count = float(data['count'])
        same_srv_rate = float(data['same_srv_rate'])
        serror_rate = float(data['serror_rate'])
        flag = float(data['flag'])
        logged_in = float(data['logged_in'])

        feature_columns = [
            'duration', 'src_bytes', 'dst_bytes',
            'count', 'same_srv_rate', 'serror_rate',
            'flag', 'logged_in'
        ]

        features = pd.DataFrame([[
            duration, src_bytes, dst_bytes,
            count, same_srv_rate, serror_rate,
            flag, logged_in
        ]], columns=feature_columns)

        prediction = model.predict(features)[0]
        prob = model.predict_proba(features)[0]
        confidence = round(max(prob) * 100, 2)

        result = "Attack" if prediction == 1 else "Normal"

        
        if result == "Attack":
            block_ip(ip, "Attack detected")

       
        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO predictions 
            (duration, src_bytes, dst_bytes, count, same_srv_rate, serror_rate, flag, logged_in, result)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            duration, src_bytes, dst_bytes,
            count, same_srv_rate, serror_rate,
            flag, logged_in, result
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return render_template(
            'results.html',
            result=result,
            probability=confidence
        )

    except Exception as e:
        return f"Error: {str(e)}"


#upload route
@app.route('/upload')
def upload():
    return render_template("upload.html")

#upload csv
@app.route('/upload_csv', methods=['POST'])
def upload_csv():
    file = request.files.get('file')

    if not file or file.filename == '':
        return "No file selected"

    if not file.filename.endswith('.csv'):
        return "Upload CSV only"

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    try:
        df = pd.read_csv(filepath)

        required_cols = [
            'duration', 'src_bytes', 'dst_bytes',
            'count', 'same_srv_rate', 'serror_rate',
            'flag', 'logged_in'
        ]

        if not all(col in df.columns for col in required_cols):
            return f"CSV must contain: {required_cols}"

        features = df[required_cols].copy()
        features = features.astype(float)

        predictions = model.predict(features)

        df['Result'] = ["Attack" if x == 1 else "Normal" for x in predictions]

        conn = connect_db()
        cursor = conn.cursor()

        for _, row in df.iterrows():
            cursor.execute("""
                INSERT INTO predictions 
                (duration, src_bytes, dst_bytes, count, same_srv_rate, serror_rate, flag, logged_in, result)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                row['duration'], row['src_bytes'], row['dst_bytes'],
                row['count'], row['same_srv_rate'], row['serror_rate'],
                row['flag'], row['logged_in'], row['Result']
            ))

        conn.commit()
        cursor.close()
        conn.close()

        return df.to_html(index=False, classes="result-table")

    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == "__main__":
    app.run(debug=True)
