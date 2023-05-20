from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import jwt

SECRET_KEY = 'your-secret-key'  # Note: This should be a complex key stored securely 

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + os.path.join(basedir, 'app.sqlite')

db = SQLAlchemy(app)
ma = Marshmallow(app)
CORS(app)


bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    description = db.Column(db.String(120), nullable=False)

class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User

class TaskSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Task

user_schema = UserSchema()
users_schema = UserSchema(many=True)

task_schema = TaskSchema()
tasks_schema = TaskSchema(many=True)

@app.route('/user', methods=['POST'])
def add_user():
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=pw_hash)
    db.session.add(new_user)
    db.session.commit()
    
    return user_schema.jsonify(new_user)


@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    user = User.query.filter_by(username=username).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    token = jwt.encode({
        'sub': user.id,
        'iat': datetime.utcnow(),  # issued at
        'exp': datetime.utcnow() + timedelta(minutes=30)},  # expires at
        SECRET_KEY)

    return jsonify({'token': token})

@app.route('/verify', methods=['GET'])
def verify():
    token = request.headers.get('Authorization')  # Token sent as Bearer token in header

    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        current_user = User.query.filter_by(id=data['sub']).first()
    except Exception as e:
        return jsonify({'message': 'Token is invalid'}), 401

    return jsonify({'message': 'Token is valid', 'user': user_schema.dump(current_user)})



@app.route('/user', methods=['GET'])
def get_users():
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result)

@app.route('/user/<id>', methods=['GET'])
def get_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    return user_schema.jsonify(user)

@app.route('/user/<id>', methods=['PUT'])
def update_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    username = request.json['username']
    email = request.json['email']
    user.email = email
    user.username = username
    db.session.commit()
    return user_schema.jsonify(user)

@app.route('/user/<id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    db.session.delete(user)
    db.session.commit()
    return user_schema.jsonify(user)

@app.route('/task', methods=['POST'])
def add_task():
    user_id = request.json['user_id']
    description = request.json['description']
    new_task = Task(user_id=user_id, description=description)
    db.session.add(new_task)
    db.session.commit()
    return task_schema.jsonify(new_task)

@app.route('/task', methods=['GET'])
def get_tasks():
    all_tasks = Task.query.all()
    result = tasks_schema.dump(all_tasks)
    return jsonify(result)

@app.route('/task/<id>', methods=['GET'])
def get_task(id):
    task = Task.query.get(id)
    if not task:
        return jsonify({'message': 'Task not found!'}), 404
    return task_schema.jsonify(task)

@app.route('/task/<id>', methods=['PUT'])
def update_task(id):
    task = Task.query.get(id)
    if not task:
        return jsonify({'message': 'Task not found!'}), 404
    description = request.json['description']
    task.description = description
    db.session.commit()
    return task_schema.jsonify(task)

@app.route('/task/<id>', methods=['DELETE'])
def delete_task(id):
    task = Task.query.get(id)
    if not task:
        return jsonify({'message': 'Task not found!'}), 404
    db.session.delete(task)
    db.session.commit()
    return task_schema.jsonify(task)

@app.route('/user/<id>/tasks', methods=['GET'])
def get_user_tasks(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    tasks = Task.query.filter_by(user_id=id).all()
    return jsonify({
        'user': user_schema.dump(user),
        'tasks': tasks_schema.dump(tasks)
    })

@app.route('/users/tasks', methods=['GET'])
def get_all_users_tasks():
    users = User.query.all()
    users_tasks = []
    for user in users:
        tasks = Task.query.filter_by(user_id=user.id).all()
        users_tasks.append({
            'user': user_schema.dump(user),
            'tasks': tasks_schema.dump(tasks)
        })
    return jsonify(users_tasks)


if __name__ == '__main__':
    app.run(debug=True)