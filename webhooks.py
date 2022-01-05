# -*- coding: utf-8 -*-
#
# Copyright (C) 2014, 2015, 2016 Carlos Jenkins <carlos@jenkins.co.cr>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import hashlib
import logging
import os
import hmac
import requests
from sys import stderr, hexversion

from json import loads, dumps
from subprocess import Popen, PIPE
from tempfile import mkstemp
from os import access, X_OK, remove, fdopen
from os.path import isfile, abspath, normpath, dirname, join, basename

from ipaddress import ip_address, ip_network
from flask import Flask, request, abort

logging.basicConfig(stream=stderr, level=logging.INFO)

application = Flask(__name__)


@application.route('/hec-monolith/', methods=['GET', 'POST'])
def index():
	"""
	Main WSGI application entry.
	"""
	
	path = normpath(abspath(dirname(__file__)))
	
	# Only POST is implemented
	if request.method != 'POST':
		abort(501)
	
	# Load config
	with open(join(path, 'config.json'), 'r') as cfg:
		config = loads(cfg.read())
	
	check_ips(config)
	enforce_secret(config)
	
	event = get_event()
	# Implement ping
	if event == 'ping':
		logging.info("Event was ping")
		return dumps({'msg': 'pong'})
	
	# Gather data
	try:
		payload = request.get_json()
	except Exception:
		logging.warning('Request parsing failed')
		abort(400)
	
	branch = get_branch(event, payload)
	
	name = get_name(payload)
	
	meta = {
		'name': name,
		'branch': branch,
		'event': event
	}
	logging.info('Metadata:\n{}'.format(dumps(meta)))
	
	# Skip push-delete
	if event == 'push' and payload['deleted']:
		logging.info('Skipping push-delete event for {}'.format(dumps(meta)))
		return dumps({'status': 'skipped'})
	
	hooks_dir = config.get('hooks_path', join(path, 'hooks'))
	scripts = get_scripts(branch, hooks_dir, meta, name)
	
	if not scripts:
		return dumps({'status': 'nop'})
	
	logging.info('Running scripts:' + str(scripts))
	# Save payload to temporal file
	osfd, tmpfile = mkstemp()
	with fdopen(osfd, 'w') as pf:
		pf.write(dumps(payload))
	
	# Run scripts
	ran = {}
	for s in scripts:
		
		proc = Popen(
			[s, tmpfile, event],
			stdout=PIPE, stderr=PIPE
		)
		stdout, stderr = proc.communicate()
		
		ran[basename(s)] = {
			'returncode': proc.returncode,
			'stdout': stdout.decode('utf-8'),
			'stderr': stderr.decode('utf-8'),
		}
		
		# Log errors if a hook failed
		if proc.returncode != 0:
			logging.error('{} : {} \n{}'.format(
				s, proc.returncode, stderr
			))
	
	# Remove temporal file
	remove(tmpfile)
	
	info = config.get('return_scripts_info', False)
	if not info:
		return dumps({'status': 'done'})
	
	output = dumps(ran, sort_keys=True, indent=4)
	logging.info(output)
	return output

def get_event():
	event = request.headers.get('X-Event-Key')
	
	# For a pr merge the eventKey looked like pr:merged and we want this method to just return "merged"
	
	# if event contains ':' we should split on ':' and take the last part
	if ':' in event:
		event = event.split(':')[-1]
	
	return event

def get_name(payload):
	# All current events have a repository, but some legacy events do not,
	# so let's be safe
	# name = payload['repository']['name'] if 'repository' in payload else None
	if 'repository' in payload:
		name = payload['repository']['name']
	elif 'pullRequest' in payload:
		name = payload['pullRequest']['toRef']['repository']['name']
	else:
		name = None
	return name

def get_scripts(branch, hooks_dir, meta, name):
	# Possible hooks
	paths = []
	if branch and name:
		paths.append(join(hooks_dir, '{event}-{name}-{branch}'.format(**meta)))
	if name:
		paths.append(join(hooks_dir, '{event}-{name}'.format(**meta)))
	paths.append(join(hooks_dir, '{event}'.format(**meta)))
	paths.append(join(hooks_dir, 'all'))
	
	# Check permissions
	scripts = []
	for s in paths:
		if os.path.commonprefix((os.path.realpath(s), hooks_dir)) != hooks_dir:
			# Make sure we're not trying to run a script outside the hooks dir
			logging.error('{} is not in {}'.format(s, hooks_dir))
		if isfile(s):
			if access(s, X_OK):
				scripts.append(s)
			else:
				logging.warning('X_OK Permission denied for {}'.format(s))
	return scripts

def check_ips(config):
	# Allow Github IPs only
	if config.get('github_ips_only', True):
		src_ip = ip_address(
			u'{}'.format(request.access_route[0])  # Fix stupid ipaddress issue
		)
		whitelist = requests.get('https://api.github.com/meta').json()['hooks']
		
		for valid_ip in whitelist:
			if src_ip in ip_network(valid_ip):
				break
		else:
			logging.error('IP {} not allowed'.format(src_ip))
			abort(403)

def enforce_secret(config):
	# Enforce secret
	secret = config.get('enforce_secret', '')
	if secret:
		# Only SHA1 is supported
		header_signature = request.headers.get('X-Hub-Signature')
		if header_signature is None:
			abort(403)
		
		sha_name, signature = header_signature.split('=')
		
		hexdigest = build_digest(secret, sha_name)
		
		verified = verify_digest(hexdigest, signature)
		
		if not verified:
			abort(403)

def verify_digest(hexdigest, signature):
	# Python prior to 2.7.7 does not have hmac.compare_digest
	verified = False
	if hexversion >= 0x020707F0:
		verified = hmac.compare_digest(str(hexdigest), str(signature))
	else:
		# What compare_digest provides is protection against timing
		# attacks; we can live without this protection for a web-based
		# application
		verified = str(hexdigest) == str(signature)
	return verified

def build_digest(secret, sha_name):
	dmod = None
	if sha_name == 'sha1':
		dmod = hashlib.sha1
	if sha_name == 'sha256':
		dmod = hashlib.sha256
	if dmod is None:
		abort(501)
	# HMAC requires the key to be bytes, but data is string
	mac = hmac.new(str(secret), msg=request.data, digestmod=dmod)
	hexdigest = mac.hexdigest()
	return hexdigest

# keeping this as a reference.
def get_branch_github(event, payload):
	# Determining the branch is tricky, as it only appears for certain event
	# types an at different levels
	branch = None
	try:
		# Case 1: a ref_type indicates the type of ref.
		# This true for create and delete events.
		if 'ref_type' in payload:
			if payload['ref_type'] == 'branch':
				branch = payload['ref']
		
		# Case 2: a pull_request object is involved. This is pull_request and
		# pull_request_review_comment events.
		elif 'pull_request' in payload:
			# This is the TARGET branch for the pull-request, not the source
			# branch
			branch = payload['pull_request']['base']['ref']
		
		elif event in ['push']:
			# Push events provide a full Git ref in 'ref' and not a 'ref_type'.
			branch = payload['ref'].split('/', 2)[2]
	
	except KeyError:
		# If the payload structure isn't what we expect, we'll live without
		# the branch name
		pass
	return branch

# Mostly care about pullRequests for now.
def get_branch(event, payload):
	branch = None
	try:
		if 'pullRequest' in payload:
			branch = payload['pullRequest']['toRef']['displayId']
		elif 'changes' in payload:
			branch = payload['changes'][0]['refId'].split('/', 2)[2]
	
	except KeyError:
		# If the payload structure isn't what we expect, we'll live without
		# the branch name
		pass
	return branch

if __name__ == '__main__':
	application.run(debug=True, host='0.0.0.0')
