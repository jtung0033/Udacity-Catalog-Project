#! /usr/bin/env python3

import json
import random
import string
from functools import wraps

import httplib2
import requests
from flask import Flask, render_template, request
from flask import redirect, url_for, flash, jsonify, make_response
from flask import session as login_session
from oauth2client.client import FlowExchangeError, OAuth2WebServerFlow
from oauth2client.client import flow_from_clientsecrets
from sqlalchemy import asc, create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User, engine, GameSystem, Game
from web import google_web

state = ''.join(random.choice(
    string.ascii_uppercase + string.digits)for x in range(32))

CLIENT_ID = json.loads(open(
    'client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = 'Game Catalog'


app = Flask(__name__)


engine = create_engine('sqlite:///gamecatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def show_login():
    login_session['state'] = state
    return render_template('login.html', STATE=login_session['state'])


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
        login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


def create_user(login_session_dict):
    new_user = User(
        name=login_session_dict['username'],
        email=login_session_dict['email'],
        picture=login_session_dict['picture']
    )
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session_dict['email']).one()
    return user.id


@app.route('/googledisconnect')
def googledisconnect():
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        # For some reason token was Invalid
        response = make_response(json.dumps(
            'Failed to revoke token for user'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


def remove_session():
    sesh = login_session.copy()
    for (key, value) in sesh.items():
        del login_session[key]


#View Game Systems
@app.route('/gameSystem/<int:gameSystem_id>/game/JSON')
def game_system_option_json(gameSystem_id):
    items = session.query(GameSystem).filter_by(
        gameSystem_id=gameSystem_id).all()
    if not items:
        return jsonify("No such Game System exists")
    return jsonify(Game=[i.serialize for i in items])


@app.route('/gameSystem/<int:gameSystem_id>/game/<int:game_id>/JSON')
def game_item_json(gameSystem_id, game_id):
    try:
        game = session.query(Game).filter_by(
            id=game_id, gameSystem_id=gameSystem_id
        ).one()
    except:
        return jsonify("No such game exists")
    return jsonify(Game=game.serialize)


@app.route('/gameSystem/JSON')
def GameSystems_json():
    gameSystem=session.query(GameSystem).all()
    return jsonify(gameSystem=[r.serialize for r in gameSystem])


@app.route('/')
@app.route('/gameSystem/')
def show_gameSystem():
    gameSystem = session.query(GameSystem).all()
    if 'username' not in login_session:
        return render_template(
        'gameSystem.html',
        gameSystem=gameSystem,
        login_session=login_session)
    return render_template('gameSystem.html', gameSystem=gameSystem)


# Create new game system
@app.route('/gameSystem/new',methods=['GET', 'POST'])
def new_gameSystem():
    if 'username' not in login_session:
        flash('Must be logged in to make changes!!')
        return redirect('/login')	
    if request.method == 'POST':
        new_gameSystem_obj = GameSystem(
            name=request.form['name'],
            user_id=login_session['username']
        )
        session.add(new_gameSystem_obj)
        flash(
            'New %s Successfully Created' %
            new_gameSystem_obj.name
        )
        session.commit()
        return redirect(url_for('show_gameSystem'))
    else:
        return render_template('newgamesystem.html')


# Update a game system
@app.route('/gameSystem/<int:gameSystem_id>/edit', methods=['GET', 'POST'])
def update_gameSystem(gameSystem_id):
    if 'username' not in login_session:
        flash('Must be logged in to make changes!!')
        return redirect('/login')
    try:
        updated_gameSystem = session.query(GameSystem).filter_by(
            id=gameSystem_id).one()
    except:
        return "Game System Does Not Exist."
    if login_session['username'] != updated_gameSystem.user_id:
        flash('You do not have access to update this game system!')
        return redirect(url_for('show_gameSystem'))
    if request.method == 'POST':
        if request.form['name'] != updated_gameSystem.name:
            updated_gameSystem.name = request.form['name']
            flash('Game System Updated to %s' % updated_gameSystem.name)
            return redirect(url_for('show_gameSystem'))
    else:
        return render_template('updategamesystem.html', 
            gameSystem=updated_gameSystem)


#Delete a game system
@app.route('/gameSystem/<int:gameSystem_id>/delete', methods=['GET', 'POST'])
def delete_gameSystem(gameSystem_id):
    if 'username' not in login_session:
        flash('Must be logged in to make changes!!')
        return redirect('/login')	
    try:
        gameSystem_to_delete = session.query(GameSystem).filter_by(
            id=gameSystem_id).one()
    except:
        return "Game System Does Not Exist."
    if login_session['username'] != gameSystem_to_delete.user_id:
        flash('You do not have access to delete this game system!')
        return redirect(url_for('show_gameSystem'))
    if request.method == 'POST':
        session.delete(gameSystem_to_delete)
        games_to_delete = session.query(Game).filter_by(
            gameSystem_id=gameSystem_id).all()
        for delete_game in games_to_delete:
            session.delete(delete_game)
            flash('%s Deleted From Database' %gameSystem_to_delete.name)
            session.commit()    		
        return redirect(url_for('show_gameSystem'))
    else:
        return render_template('deletegamesystem.html',
            gameSystem=gameSystem_to_delete)


#Show a game system's available games
@app.route('/gameSystem/<int:gameSystem_id>')
@app.route('/gameSystem/<int:gameSystem_id>/game')
def show_game(gameSystem_id):
    try:
        gameSystem = session.query(GameSystem).filter_by(
            id=gameSystem_id).one()
    except:
        return "Game System Does Not Exist."
    items = session.query(Game).filter_by(gameSystem_id=gameSystem_id).all()
    return render_template(
        'game.html',
        items = items,
        gameSystem = gameSystem,
        login_session = login_session
    )


#Create a new game item
@app.route('/gameSystem/<int:gameSystem_id>/game/new', methods=['GET','POST'])
def new_game(gameSystem_id):
    if 'username' not in login_session:
        flash('Must be logged in to make changes!!')
        return redirect('/login')	
    try:
        gameSystem = session.query(GameSystem).filter_by(
            id=gameSystem_id).one()
    except:
        return "Game System Does Not Exist."
    if request.method == 'POST':
        new_item = Game(
            name=request.form['name'],
            description=request.form['description'],
            gameSystem_id=gameSystem_id,
            user_id=gameSystem.user_id,
        )
        session.add(new_item)
        session.commit()
        flash('%s Successfully Created' %new_item.name)
        return redirect(url_for('show_game', gameSystem_id=gameSystem_id))
    else:
        return render_template('newgame.html', gameSystem_id=gameSystem_id)


#Update a game 
@app.route('/gameSystem/<int:gameSystem_id>/game/<int:game_id>/update',
    methods=['GET','POST'])
def update_game(gameSystem_id, game_id):
    if 'username' not in login_session:
        flash('Must be logged in to make changes!!')
        return redirect('/login')	
    try:
        updated_item = session.query(Game).filter_by(
            id=game_id).one()
    except:
        return "Game does not exist."
    try:
        gameSystem = session.query(GameSystem).filter_by(
            id=gameSystem_id).one()
    except:
        return "Game System Does Not Exist."
    if login_session['username'] != updated_item.user_id:
        flash('You do not have access to update this game!')
        return redirect(url_for('show_gameSystem'))
    if request.method == 'POST':
        for (key, value) in request.form.items():
            setattr(updated_item, key, value)
            session.add(updated_item)
            session.commit()
            flash('%s Updated' % updated_item.name)
            return redirect(url_for('show_game', 
                gameSystem_id=gameSystem_id))
    else:
        return render_template(
            'updategame.html',
            gameSystem_id=gameSystem_id,
            game_id=game_id,
            item=updated_item
        )


#Delete a game
@app.route('/gameSystem/<int:gameSystem_id>/game/<int:game_id>/delete',
    methods=['GET', 'POST'])
def delete_game(gameSystem_id, game_id):
    if 'username' not in login_session:
        flash('Must be logged in to make changes!!')
        return redirect('/login')	
    try:
        item_to_delete = session.query(Game).filter_by(
            id=game_id).one()
    except:
        return "Game does not exist."
    try:
        gameSystem = session.query(GameSystem).filter_by(
            id=gameSystem_id).one()
    except:
        return "Game System Does Not Exist."
    if login_session['username'] != item_to_delete.user_id:
        flash('You do not have access to delete this game!')
        return redirect(url_for('show_gameSystem'))
    if request.method == 'POST':
        session.delete(item_to_delete)
        session.commit()
        flash('Game Deleted')
        return redirect(url_for('show_game', gameSystem_id=gameSystem_id))
    else:
        return render_template('deletegame.html', item=item_to_delete)


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        remove_session()
        flash("You have successfully been logged out.")
        return redirect(url_for('show_gameSystem'))
    else:
        flash("You were not logged in")
        return redirect(url_for('show_gameSystem'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(
        host='0.0.0.0',
        port=5000
    )	