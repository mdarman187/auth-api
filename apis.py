from flask import Flask, render_template, url_for, request, redirect, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import datetime
from functools import wraps
import jwt
import pandas


app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth-api.db'

db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agencyid = db.Column(db.String(100)) 
    agencyname = db.Column(db.String(50))
    email = db.Column(db.String(50))
    password = db.Column(db.String(80))

class Asset(db.Model):
    __tablename__ = "picklist"
    id = db.Column(db.Integer, primary_key=True)
    picklistId = db.Column(db.Text)
    optionId = db.Column(db.Integer)
    minValue = db.Column(db.Float)
    maxValue = db.Column(db.Float)
    value = db.Column(db.Float)
    status = db.Column(db.Text)
    externalCode = db.Column(db.Text)
    parentOptionId = db.Column(db.Integer)
    en_US =db.Column(db.Text)
    en_DEBUG =db.Column(db.Text)
    en_GB =db.Column(db.Text)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(agencyid=data['agencyid']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/forgetpassword')
def forgetPassword():
  print("redirect to forget password page")
  return redirect("https://www.google.com")


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = Users.query.filter_by(agencyid=auth.username).first()

    if user.password == auth.password:
        token = jwt.encode({'agencyid' : user.agencyid, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8'),'message' : 'Login Successful!'})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@app.route('/signup', methods=['POST'])
def signup():

  data = request.get_json()
  new_user = Users(agencyid = data['agencyid'], agencyname = data['agencyname'], email = data['email'], password = data['password'])
  db.session.add(new_user)
  db.session.commit()

  return jsonify({'message' : 'Signup Successful!'})


@app.route('/import-picklist')
def importPicklist():
    engine = db.get_engine()
    csv_file_path = 'picklist.csv'

# Read CSV with Pandas
    with open(csv_file_path, 'r') as file:
        df = pd.read_csv(file)

# Insert to DB
    df.to_sql('picklist',con=engine,index=False,index_label='id',if_exists='replace')

    return jsonify({'message' : 'imported Successful!'})


@app.route('/resetpassword', methods=['PUT'])
@token_required
def resetpassword(current_user):
    resetuser = Users.query.filter_by(agencyid=current_user.agencyid).first()

    if not resetuser:
        return jsonify({'message' : 'No user found!'})

    data = request.get_json()

    if resetuser.email == data['email'] and resetuser.password == data['currentPassword']:
      resetuser.password = data['newPassword']
      db.session.commit()
      return jsonify({'message': 'Password changed successfully'})
    else:
      return jsonify({'message' : 'Incorrect Credentials!'})

if __name__ == '__main__':
    app.run(debug=True)