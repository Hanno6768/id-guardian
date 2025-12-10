from flask import Flask, render_template

app = Flask(__name__)
app.config['SERVER_NAME'] = '127.0.0.1:5000'
app.config['APPLICATION_ROOT'] = '/'

@app.route("/")
def index():
    return render_template("layout.html")

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)


