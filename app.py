from flask import Flask, session, make_response, redirect, request, render_template, url_for
from flask_caching import Cache
from config import Config
from functions import createStateKey, getToken, getUserInformation, getAllTopTracks, revoke_spotify_token, logging_out_of_spotify
import time
import logging
import requests

app = Flask(__name__)
app.config.from_object(Config)
cache = Cache(app)

@app.route("/")
def hello_world():
    return "<p>Welcome to the world, Spotivibe!</p>"

@app.route('/authorize')
def authorize():
  client_id = app.config['CLIENT_ID']
  redirect_uri = app.config['REDIRECT_URI']
  scope = app.config['SCOPE']

	# state key used to protect against cross-site forgery attacks
  state_key = createStateKey(15)
  session['state_key'] = state_key

	# redirect user to Spotify authorization page
  authorize_url = 'https://accounts.spotify.com/en/authorize?'
  parameters = 'response_type=code&client_id=' + client_id + '&redirect_uri=' + redirect_uri + '&scope=' + scope + '&state=' + state_key
  response = make_response(redirect(authorize_url + parameters))

  return response

@app.route('/callback')
def callback():
	# make sure the response came from Spotify
	if request.args.get('state') != session['state_key']:
		return render_template('index.html', error='State failed.')
	if request.args.get('error'):
		return render_template('index.html', error='Spotify error.')
	else:
		code = request.args.get('code')
		session.pop('state_key', None)

		# get access token to make requests on behalf of the user
		payload = getToken(code)
		if payload != None:
			session['token'] = payload[0]
			session['refresh_token'] = payload[1]
			session['token_expiration'] = time.time() + payload[2]
		else:
			return render_template('index.html', error='Failed to access token.')

	current_user = getUserInformation(session)
	session['user_id'] = current_user['id']
	logging.info('new user:' + session['user_id'])

	return redirect(session['previous_url'])

@app.route('/tracks',  methods=['GET'])
def tracks():
	if session.get('token')==None:
		print("token : None\n")
	else:
		print("token : " + str(session.get('token')) + "\n")
	if session.get('token_expiration')==None:
		print("expiration : None\n")
	else:
		print("expiration : " + str(session.get('token_expiration')) + "\n")
	# make sure application is authorized for user
	if session.get('token') == None or session.get('token_expiration') == None:
		session['previous_url'] = '/tracks'
		return redirect('/authorize')

	# collect user information
	if session.get('user_id') == None:
		current_user = getUserInformation(session)
		session['user_id'] = current_user['id']

	track_ids = getAllTopTracks(session)

	if track_ids == None:
		return render_template('index.html', error='Failed to gather top tracks.')
		
	return render_template('tracks.html', track_ids=track_ids)

@app.after_request
def after_request_action(response):
	if request.url == 'https://accounts.spotify.com/logout':
		time.sleep(2)
		print("Je suis dans after_logout\n\n\n\n\n\n\n\n\n")
		session['token']=None
		session['token_expiration']=None
		return redirect(url_for('hello_world'))
	return response

@app.route('/logout', methods=['POST'])
def logout():
	# logging_out_of_spotify()
	# session.clear()
	# cache.clear()
	if session['token'] != None or session['token_expiration'] != None:
		print("flag\n\n\n\n\n\n")
		response = requests.post('https://accounts.spotify.com/api/token/revoke', data={'token':session['token']})
		if response.status_code ==200:
			print("Token révoqué avec succès\n\n\n\n\n\n")
		else:
			print("Erreur lors de la révocation du token" + str(response.status_code) + "\n\n\n\n\n\n")
	print('Je suis dans /logout\n\n\n\n\n')
	return redirect('https://accounts.spotify.com/logout')