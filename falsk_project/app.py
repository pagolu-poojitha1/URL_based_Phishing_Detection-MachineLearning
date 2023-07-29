import numpy as np
from flask import Flask,request,jsonify,render_template
import pickle
import featurextraction

app=Flask(__name__)

model=pickle.load(open('Phishing_Website.pkl','rb'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict')
def predict():
    return render_template('final.html')

#Fetches the URL given by the URL and passes to inputScript 

@app.route('/y_predict', methods=['POST'])

@app.route('/y_predict', methods=['POST'])
def y_predict():
    url = request.form['url']
    checkprediction = featurextraction.main(url) 
    prediction = model.predict(checkprediction) 
    print(prediction) 
    output=prediction[0] 
    if output == 1: 
        pred = "Your are safe!! This is a Legitimate Website."
    else:
        pred = "You are on the wrong site. Be cautious!" 
    return render_template('final.html', prediction_text=pred, url=url)


# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)