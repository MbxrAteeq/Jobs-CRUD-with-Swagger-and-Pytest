import os
import re
import datetime
import jwt as jwt1
import geopy.distance 
from apispec import APISpec
from functools import wraps
from flasgger import Swagger
from sqlalchemy.sql import func
from sqlalchemy import DateTime
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:MA5xy6ZR149er@localhost:5432/jobs"
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:://' + os.environ.get('USER') + ':' + os.environ.get('PASSWORD') + '@' + os.environ.get('HOST') + ':5432/' + os.environ.get('DATABASE')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')

db = SQLAlchemy(app)

# Marshmallow to serialize Data
ma = Marshmallow(app)

swagger = Swagger(app)
#http://localhost:5000/apidocs/


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(200), nullable=False)
    lastName = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True, nullable=False)
    userName = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class Jobs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.String(500))
    jobTitle = db.Column(db.String(500))
    jobDesc = db.Column(db.String(500))
    jobRate = db.Column(db.String(500))
    latitude = db.Column(db.String(500))
    longitude = db.Column(db.String(500))
    isActive = db.Column(db.Boolean, default=True, nullable=False)
    jobCreated = db.Column(DateTime(timezone=True), server_default=func.now())
    jobUpdated = db.Column(DateTime(timezone=True), onupdate=func.now())


# JWT Required Decorator
def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = None
       if 'x-access-tokens' in request.headers:
           token = request.headers['x-access-tokens']

       if not token:
           return jsonify({'message': 'a valid token is missing'}), 401
       try:
           data = jwt1.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
           current_user = Users.query.filter_by(id=data['id']).first()
       except:
           return jsonify({'message': 'Token is INVALID or EXPIRED'}), 405
       return f(current_user, *args, **kwargs)
   return decorator


def validations(username, email, password):
    data = Users.query.filter((Users.userName == username) | (Users.email == email)).first()
    if data:
        return ("Username and email must be unique")

    if not re.match(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$', email):
        return ("Invalid Email")

    if len(password) < 10:
        return ("Password must be 10 characters")



@app.route('/signUp', methods=['POST'])
def signUp():
    """
    file: swaggerTemplates/signUp.yml
    """
    data = request.get_json()
    msg = validations(data['userName'], data['email'], data['password'])
    if msg:
        return jsonify({"msg":msg}),401

    newUser = Users(firstName = data['firstName'], lastName = data['lastName'], email = data['email'], userName = data['userName'],
    password = generate_password_hash(data['password'], method = 'sha256'))

    db.session.add(newUser)
    db.session.commit()

    return jsonify({'message':'New User Created'}), 200


@app.route('/refresh', methods=['POST'])
def refresh():
    refresh = request.cookies.get('refresh_token')
    try:
        decoded = jwt1.decode(refresh, app.config['JWT_SECRET_KEY'], algorithms=["HS384"])
        user = Users.query.filter(decoded['id'] == Users.id).first()
        if user:
            access_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=59)}, app.config['JWT_SECRET_KEY'], "HS256")
            refresh_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(weeks=1)}, app.config['JWT_SECRET_KEY'], "HS384")
            resp = jsonify({'x-access-tokens': access_token})
            resp.set_cookie('refresh_token', refresh_token, httponly = True)
            return resp, 200
    except:

        return jsonify({'msg':'Unauthorized Access'}), 401
    return jsonify({'msg': "Refresh cookies not valid"})



#for jwt authentication
@app.route('/signIn', methods=['POST'])
def signIn():
    """
    file: swaggerTemplates/signIn.yml
    """
    auth = request.authorization

    if not auth or not auth.username or not auth.password: 
        return jsonify('could not verify', 401, {'Authentication': 'login required"'})   
    user = Users.query.filter_by(userName=auth.username).first()

    if not user:
        return jsonify({'message':'Login Unsuccessfull'}), 401

    if check_password_hash(user.password, auth.password):
        access_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=59)}, app.config['JWT_SECRET_KEY'], "HS256")
        refresh_token = jwt1.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=1)}, app.config['JWT_SECRET_KEY'], "HS384")
        resp = jsonify({'x-access-tokens': access_token})
        resp.set_cookie('refresh_token', refresh_token, httponly = True)

        return resp, 200

    return jsonify({'message':'Login Unsuccessfull'}), 401


# Marshmellow Schema for serilizing data
class JobsSchema(ma.Schema):

    class Meta:
        model = Jobs
        fields = ('id','userId','jobTitle','jobDesc','jobRate',str('latitude'),str('longitude'),'isActive','jobCreated','jobUpdated')
job_schema = JobsSchema()
jobs_schema = JobsSchema(many=True)


#Jobs API CRUD Operation

#Jobs GET All jobs with kilometer filtration  using lat and long Endpoint
@app.route('/alljobs', methods=['GET'])
@token_required
def get_all_job(current_user):
    """
    file: swaggerTemplates/getJobs.yml
    """
    lat = request.args.get('latitude', type=float , default=None)
    longi = request.args.get('longitude', type=float , default=None)
    km = request.args.get('kilometer', type=int , default=15)
    if lat and longi:
        nearbyJobs = Jobs.query.filter(
            (func.degrees(
                func.acos(
                    func.sin(func.radians(lat)) * func.sin(func.radians(Jobs.latitude)) + 
                    func.cos(func.radians(lat)) * func.cos(func.radians(Jobs.latitude)) * 
                    func.cos(func.radians(longi-Jobs.longitude))
                )
            ) * 60 * 1.1515 * 1.609344) <= km)
        output = []
        for jobs in nearbyJobs:
            # Lat and long were in decimal form and Jsonify cant serilaze decimal so we convert them to string.
            jobs.latitude = str(jobs.latitude)
            jobs.longitude = str(jobs.longitude)
            output.append(jobs)
        job_data = jobs_schema.dump(output)

        if not job_data:
            return jsonify({"msg":"No Data Found"}), 404

        return jsonify({'message':job_data}), 200

    # For complete data from Jobs table
    allJobs = Jobs.query.all()
    if allJobs:
        output = []
        for jobs in allJobs:
            jobs.latitude = str(jobs.latitude)
            jobs.longitude = str(jobs.longitude)
            output.append(jobs)
        job_data = jobs_schema.dump(output)

    return jsonify({'data':job_data}), 200


#Create new job Endpoint
@app.route('/jobs', methods=['POST'])
@token_required
def add_job(current_user):
    """
    file: swaggerTemplates/addJobs.yml
    """
    data = request.get_json()

    new_job = Jobs(userId = current_user.id, jobTitle = data['jobTitle'], jobDesc = data['jobDesc'], jobRate = data['jobRate'], 
    latitude = data['latitude'], longitude = data['longitude'])

    db.session.add(new_job)
    db.session.commit()
    
    return jsonify({'msg':'Job Created'}), 200


#Edit job(by id) Endpoint
@app.route("/jobs/<id>", methods=['PUT'])
@token_required
def edit_job(current_user, id):
    """
    file: swaggerTemplates/editJobs.yml
    """
    data = request.get_json()
    value = Jobs.query.filter_by(id=id).first()

    if not value:
        return jsonify({'msg':'Data does not exist in DB'}), 404

    value.jobTitle = data['jobTitle']
    value.jobDesc = data['jobDesc']
    value.jobRate = data['jobRate']
    value.latitude = data['latitude']
    value.longitude = data['longitude']
    value.isActive = data['isActive']
    value.userId = current_user.id

    db.session.commit()
    return jsonify({'msg':'Job Updated'}), 200


#Soft delete a job(by id) Endpoint
@app.route("/jobs/<id>", methods=['DELETE'])
@token_required
def del_job(current_user, id):
    """
    file: swaggerTemplates/delJobs.yml
    """
    cId = str(current_user.id)
    job = Jobs.query.filter(id==Jobs.id, cId == Jobs.userId).first()

    if not job:
        return jsonify({'msg':'No Data or Unathorized User for Deletion'}), 404

    job.isActive = False
    db.session.commit()
    return jsonify({'message':'Delete Operation Completed'}), 200

if __name__ == '__main__':        
    app.run(debug=True)