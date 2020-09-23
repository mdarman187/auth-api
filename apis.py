from flask import Flask, render_template, url_for, request, redirect, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import datetime
from functools import wraps
import jwt


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


@app.route('/forgetPassword')
def forgetPassword():
  print("redirect to forget password page")
  return redirect("https://www.google.com")


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = Users.query.filter_by(agencyid=auth.username).first()

    if not user:
        return redirect(url_for('signup'))

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


@app.route('/register')
def register():
  return jsonify({'message' : 'Registration Successful!'})


@app.route('/resetPassword', methods=['PUT'])
@token_required
def resetPassword(current_user):
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