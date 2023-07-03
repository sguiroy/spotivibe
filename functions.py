import random as rand
import string as string
from config import Config
import requests
import logging
import time
import subprocess
import pyautogui

def createStateKey(size):
	return ''.join(rand.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(size))

def getToken(code):
	token_url = 'https://accounts.spotify.com/api/token'
	authorization = Config.AUTHORIZATION
	redirect_uri = Config.REDIRECT_URI

	headers = {'Authorization': authorization, 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
	body = {'code': code, 'redirect_uri': redirect_uri, 'grant_type': 'authorization_code'}
	post_response = requests.post(token_url, headers=headers, data=body)

	# 200 code indicates access token was properly granted
	if post_response.status_code == 200:
		json = post_response.json()
		return json['access_token'], json['refresh_token'], json['expires_in']
	else:
		logging.error('getToken:' + str(post_response.status_code))
		return None
	
def getUserInformation(session):
	url = 'https://api.spotify.com/v1/me'
	payload = makeGetRequest(session, url)

	if payload == None:
		return None

	return payload

def makeGetRequest(session, url, params={}):
	headers = {"Authorization": "Bearer {}".format(session['token'])}
	response = requests.get(url, headers=headers, params=params)

	# 200 code indicates request was successful
	if response.status_code == 200:
		return response.json()

	# if a 401 error occurs, update the access token
	elif response.status_code == 401 and checkTokenStatus(session) != None:
		return makeGetRequest(session, url, params)
	else:
		logging.error('makeGetRequest:' + str(response.status_code))
		return None
	
def checkTokenStatus(session):
	if time.time() > session['token_expiration']:
		payload = refreshToken(session['refresh_token'])

		if payload != None:
			session['token'] = payload[0]
			session['token_expiration'] = time.time() + payload[1]
		else:
			logging.error('checkTokenStatus')
			return None

	return "Success"

def refreshToken(refresh_token):
	print("Flag refreshToken\n\n\n\n\n\n\n\n\n\n")
	token_url = 'https://accounts.spotify.com/api/token'
	authorization = Config.AUTHORIZATION

	headers = {'Authorization': authorization, 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
	body = {'refresh_token': refresh_token, 'grant_type': 'refresh_token'}
	post_response = requests.post(token_url, headers=headers, data=body)

	# 200 code indicates access token was properly granted
	if post_response.status_code == 200:
		return post_response.json()['access_token'], post_response.json()['expires_in']
	else:
		logging.error('refreshToken:' + str(post_response.status_code))
		return None

def getAllTopTracks(session, limit=10):
	url = 'https://api.spotify.com/v1/me/top/tracks'
	track_ids = []
	time_range = ['short_term', 'medium_term', 'long_term']

	for time in time_range:
		track_range_ids = []

		params = {'limit': limit, 'time_range': time}
		payload = makeGetRequest(session, url, params)

		if payload == None:
			return None

		for track in payload['items']:
			track_range_ids.append(track['id'])

		track_ids.append(track_range_ids)

	return track_ids

def logging_out_of_spotify():
	temp = subprocess.Popen('start https://accounts.spotify.com/logout',shell=True)
	print("Logged out from Spotify\n")
	#temp.terminate()

def revoke_spotify_token(access_token):
	headers = {
        'Authorization': 'Basic <base64_encoded_client_credentials>',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
	data = {
        'token': access_token,
        'token_type_hint': 'access_token'
    }
	if access_token==None:
		print("Already logged out.")
	else:
		response = requests.post('https://accounts.spotify.com/api/token', headers=headers, data=data)
		if response.status_code == 200:
			print("Spotify token revoked successfully.")
		else:
			print("Failed to revoke Spotify token.")