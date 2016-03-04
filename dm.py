from flask import Flask, request, redirect, abort, jsonify, make_response, current_app, send_from_directory
import json, re, urllib, httplib, os, time, base64, hmac, sha, requests, logging
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
from hashlib import sha1
from datetime import timedelta
from functools import update_wrapper
import warcpayload

dm = Flask(__name__)



def crossdomain(origin=None, methods=None, headers=None,
				max_age=21600, attach_to_all=True,
				automatic_options=True):
	if methods is not None:
		methods = ', '.join(sorted(x.upper() for x in methods))
	if headers is not None and not isinstance(headers, basestring):
		headers = ', '.join(x.upper() for x in headers)
	if not isinstance(origin, basestring):
		origin = ', '.join(origin)
	if isinstance(max_age, timedelta):
		max_age = max_age.total_seconds()

	def get_methods():
		if methods is not None:
			return methods

		options_resp = current_app.make_default_options_response()
		return options_resp.headers['allow']

	def decorator(f):
		def wrapped_function(*args, **kwargs):
			if automatic_options and request.method == 'OPTIONS':
				resp = current_app.make_default_options_response()
			else:
				resp = make_response(f(*args, **kwargs))
			if not attach_to_all and request.method != 'OPTIONS':
				return resp

			h = resp.headers

			h['Access-Control-Allow-Origin'] = origin
			h['Access-Control-Allow-Methods'] = get_methods()
			h['Access-Control-Max-Age'] = str(max_age)
			if headers is not None:
				h['Access-Control-Allow-Headers'] = headers
			return resp

		f.provide_automatic_options = False
		return update_wrapper(wrapped_function, f)
	return decorator


@dm.route("/dav/<vo>/<se>/<path:path>", methods=['PROPFIND','MKCOL','MOVE','HEAD','GET','OPTIONS','PUT', 'DELETE'])
def browser(vo,se,path):
	print "DAV browser"
	print "request method>", request.method
	print "request headers>"
	dm.logger.info("DAV API. Request Method: %s", request.method)
	dm.logger.info("VO=%s SE=%s PATH=%s", vo, se, path)
	headers = {}
	if request.method == 'MOVE':
		headers['Overwrite'] = request.headers.get('Overwrite')
		print "original destiantio type", type(request.headers.get('Destination'))
		print "vo", vo, type(vo), type(str(vo))
		print "se", type(se)
		print "pattern", type("http://glibrary.ct.infn.it/dm/dav/"+str(vo)+"/"+ str(se))
		print "replacement", type("https://" + str(se))
		print "replaced", type(request.headers.get('Destination').replace("http://glibrary.ct.infn.it/dm/dav/"+str(vo)+"/"+ str(se), "https://" + str(se)))
		headers['Destination'] = request.headers.get('Destination').replace("http://glibrary.ct.infn.it/dm/dav/"+str(vo)+"/"+ str(se), "https://" + str(se))
		print type(headers['Destination'])
	if request.headers.get('Depth'):
		headers['Depth'] = request.headers.get('Depth')
	for h, v in request.headers:
		print h, v
		#headers[h] = v
	if request.method == 'GET' or request.method == 'PUT':
		headers["X-Auth-Ip"] = request.environ['REMOTE_ADDR']
		if request.method == 'PUT' and request.headers.get('Expect'):
			headers['Expect'] = request.headers.get('Expect')
	print headers
	proxy = get_proxy(vo)

	print "vo:", vo
	print "se:", se
	print "path:", "/" + path
	#headers = {}
	#headers['Depth'] = 1

	conn = httplib.HTTPSConnection(se, cert_file=proxy, key_file=proxy)
	try:
		conn.request(request.method, '/' + path, None, headers)
	except Exception, e:
		#return HttpResponseNotFound("Network error: %s" % e)
		print "eccezione", e
		dm.logger.error(e)
		abort(500)
	resp = conn.getresponse()
	#print "risposta", resp
	print resp.status, type(resp.status)
	print resp.reason
	print resp.getheaders()
	dm.logger.debug("Status '%s' Reason '%s'", resp.status, resp.reason)
	if resp.status == 207:
		try:
			data = resp.read()
		except Exception, e:
			print "eccezione", e
			abort(500)
		href = "/"+path
		print "href>", href
		href_rel = "/dm/dav/"+vo+"/"+ se + "/" + path
		print "href_rel>", href_rel
		new_url = data.replace(href, href_rel)
		dm.logger.info("Request %s completed with status %s", request.method, resp.status, new_url)
		return new_url
	else:
		#print "response>"
		#print resp.status
		#print resp.getheaders()
		response = make_response(resp.read())
		#print "after data", response
		response.headers = resp.getheaders()
		#print "after headers", type(resp.getheaders()), response
		response.status_code = resp.status
		#print "after status", response
		dm.logger.info("Request %s completed with status %s", request.method, resp.status)
		dm.logger.debug("Response Body", response)
		print "sto restituendo la risposta", resp.status
		return response
		#abort(500)


@dm.route("/hello")
def hello():
	#abort(500)

	dm.logger.info('API /hello')


	return jsonify({'success': True, 'text': "Hello, World 22!"})

@dm.route("/whoami")
def whoami():
	if not request.environ.has_key('SSL_CLIENT_S_DN'):
		print "Environment:", request.environ
		return "you need to be authenticated"
	else:
		return request.environ['SSL_CLIENT_S_DN']

@dm.route("/<vo>/<se>/<path:path>", methods=['GET','PUT'])
def download(vo, se, path):
	if request.method == 'GET':
		print "Download API"
		print "Cookies:", request.cookies
		print "VO: ", vo

		#get_proxy(robot_serial, vo, attribute, proxy)
		proxy = get_proxy(vo)

		info = {}
		info['se'] = se
		info['path'] = path
		#print request.args.get('pippo','')
		info['robot'] = request.args.get('robot_serial','')
		info['voms'] = request.args.get('voms','')
		#link = "https://%s/%s?authip=%s" % (se, path, request.environ['REMOTE_ADDR'])
		#print "download link: ", link

		print "REMOTE_ADDR: ", request.environ['REMOTE_ADDR']
		if 'HTTP_X_FORWARDED_FOR' in request.environ:
			print "HTTP_X_FORWARDED_FOR: ", request.environ['HTTP_X_FORWARDED_FOR']
		#print request.META['HTTP_X_FORWARDED_HOST']

		if se in ['infn-se-03.ct.pi2s2.it', 'se01.grid.arn.dz','se.reef.man.poznan.pl','prod-se-03.ct.infn.it','gridsrv3-4.dir.garr.it']:
			if 'HTTP_X_FORWARDED_FOR' in request.environ:
				headers = {"X-Auth-Ip": request.environ['HTTP_X_FORWARDED_FOR']}
				path = "/%s" % path
			else:
				headers = {"X-Auth-Ip": request.environ['REMOTE_ADDR']}
				path = "/%s" % path
		else:
			headers = {}
			if 'HTTP_X_FORWARDED_FOR' in request.environ:
				path = "/%s?authip=%s" % (path, request.environ['HTTP_X_FORWARDED_FOR'])
			else:
				path = "/%s?authip=%s" % (path, request.environ['REMOTE_ADDR'])



		#path = "/%s?authip=%s" % (path, request.environ['REMOTE_ADDR'])
		print "SE:", se
		print "PATH:", path
		print "PROXY:", proxy
		print "HEADERS:", headers
		conn = httplib.HTTPSConnection(se, cert_file=proxy, key_file=proxy)
		try:
			conn.request("GET", path, None, headers)
		except Exception, e:
			#return HttpResponseNotFound("Network error: %s" % e)
			print e
			abort(500)
		resp = conn.getresponse()
		print "STATUS: ", resp.status
		print "REASON: " , resp.reason
		print "HEADERS: ", resp.getheaders()
		redirect_url = resp.getheader("location")
		print "REDIRECT URL: ", redirect_url
		if redirect_url == None:
			output = resp.read()
			print "RESPONSE: ", output
			conn.close()
			abort(404)
			#return HttpResponseNotFound("replica (%s) not found<br>%s" % (link, output))
		conn.close()
		return redirect(redirect_url)
	else:
		print "Upload PUT API"
		path_parts = path.split('/')
		filename = path_parts[len(path_parts) - 1]
		print "filename", filename
		newpath = '/'.join(path_parts[:-1])
		return put(vo, filename, se, newpath)


@dm.route("/upload/<vo>/<filename>/<se>/<path:path>")
def upload(vo, filename, se, path):

	proxy = get_proxy(vo)

	if se in ['infn-se-03.ct.pi2s2.it', 'se01.grid.arn.dz','prod-se-03.ct.infn.it']:
		#headers = {"X-Auth-Ip": request.environ['REMOTE_ADDR']}
		path = "/%s/%s" % (path, filename)
		conn = httplib.HTTPSConnection(se, cert_file=proxy, key_file=proxy)
		#conn.set_debuglevel(1)
		#conn.set_tunnel('localhost', 9090)
		empty_file = open("/tmp/empty", 'wb+')
		#register_openers()
		datagen, headers = multipart_encode({"myfile": empty_file})
		data = str().join(datagen)
		headers["X-Auth-Ip"] = request.environ['REMOTE_ADDR']
		try:
			conn.request("POST", path, data, headers)
		except Exception, e:
			print "eccezione", e
			#return HttpResponseNotFound("Network error: %s" % e)
			abort(500)

		resp = conn.getresponse()
		print "Status:", resp.status
		print resp.reason
		print resp.getheaders()
		responseTxt = resp.read()
		print responseTxt
		redirect_url = resp.getheader("location")
		print redirect_url
		if resp.status == 307:
			return jsonify({"status": resp.status, "redirect": redirect_url})
		else:
			return jsonify({"status": resp.status, "reason": resp.reason, "response": responseTxt})
	else:
		headers = {}
		path = "/%s?metacmd=post&filename=%s&metaopt=755&authip=%s" % (path, filename, request.environ['REMOTE_ADDR'])
		method = "GET"

		#path = "/%s?metacmd=post&filename=%s&metaopt=755&authip=%s" % (path, filename, request.environ['REMOTE_ADDR'])
		print "se: ", se
		print "path:", path
		conn = httplib.HTTPSConnection(se, cert_file=proxy, key_file=proxy)
		try:
			conn.request("GET", path)
		except Exception, e:
			#return HttpResponseNotFound("Network error: %s" % e)
			abort(500)
		resp = conn.getresponse()
		print resp.status
		print resp.reason
		print resp.getheaders()
		responseTxt = resp.read()
		print responseTxt
		regex = re.compile('.+action=\"(.+)\".+')
		action_url=regex.search(responseTxt)
		if action_url == None:
			return jsonify({'success': False, 'error': responseTxt})
		url = action_url.group(1)
		parsed_url = re.search('(http://.*)\?httpstoken=(.*)&httpsauthz=(.*)', url)
		dest = parsed_url.group(1)
		httpstoken = parsed_url.group(2)
		httpsauthz = parsed_url.group(3)
		resp = {'dest' : dest, 'httpstoken' : httpstoken, 'httpsauthz' : httpsauthz, 'post_url' : url}
		print resp
		return jsonify(resp)
		#return json.dumps(resp)


@dm.route("/put/<vo>/<filename>/<se>/<path:path>", methods=['GET', 'OPTIONS'])
@crossdomain(origin='*', headers=['Content-Type','Content-Disposition','X-Requested-With','X-File-Type','X-File-Name','X-File-Size'])
def put(vo, filename, se, path):

	proxy = get_proxy(vo)
	dm.logger.info("\nUPLOAD API: Request for a PUT URL for '%s' in '%s' at '%s'", filename, se, path)
	if se in ['infn-se-03.ct.pi2s2.it', 'se01.grid.arn.dz','se.reef.man.poznan.pl','prod-se-03.ct.infn.it','gridsrv3-4.dir.garr.it']:
		if 'HTTP_X_FORWARDED_FOR' in request.environ:
			headers = {"X-Auth-Ip": request.environ['HTTP_X_FORWARDED_FOR']}
		else:
			headers = {"X-Auth-Ip": request.environ['REMOTE_ADDR']}

		print "Delegating IP:", headers['X-Auth-Ip']
		dm.logger.info("Requesting client %s", headers['X-Auth-Ip'])

		#headers = {"X-Auth-Ip": request.environ['REMOTE_ADDR']}
		path = "/%s/%s" % (path, filename)
		print "path: %s " % path
		conn = httplib.HTTPSConnection(se, cert_file=proxy, key_file=proxy)
		#conn.set_debuglevel(1)
		try:
			conn.request("PUT", path, None, headers)
		except Exception, e:
			print "eccezione", e
			#return HttpResponseNotFound("Network error: %s" % e)
			dm.logger.error("Request for a PUT url to the storage '%s' failed", se)
			abort(500)

		resp = conn.getresponse()
		print "Status:", resp.status
		print resp.reason

		dm.logger.debug("response from '%s': Status '%s' Reason '%s'", se, resp.status, resp.reason)
		#dm.logger.debug("response headers %s", resp.getheaders())
		responseTxt = resp.read()
		#print responseTxt
		#dm.logger.debug("response body %s", responseTxt)
		redirect_url = resp.getheader("location")
		print redirect_url
		dm.logger.info("PUT URL for upload: '%s'", redirect_url)

		if resp.status == 307:
			return jsonify({"status": resp.status, "redirect": redirect_url})
		else:
			dm.logger.error(responseTxt)
			return jsonify({"status": resp.status, "reason": resp.reason, "response": responseTxt}), resp.status

	else:
		dm.logger.info("using old DPM SE redirect with authip. Update your storage SE")
		path = "/%s?metacmd=put&filename=%s&metaopt=755&authip=%s" % (path, filename, request.environ['REMOTE_ADDR'])
		print "se: ", se
		print "path:", path
		dm.logger.info("SE %s, Path %s", se, path)
		conn = httplib.HTTPSConnection(se, cert_file=proxy, key_file=proxy)
		try:
			conn.request("GET", path)
		except Exception, e:
			#return HttpResponseNotFound("Network error: %s" % e)
			abort(500)
		resp = conn.getresponse()
		print resp.status
		print resp.reason
		#print resp.getheaders()
		responseTxt = resp.read()
		print responseTxt
		dm.logger.debug("response from SE %s: Status %s, Reason %s", se, resp.status, rest.reason)
		dm.logger.debug("response headers", resp.getheaders())
		dm.logger.debug("response body", responseTxt)
		regex = re.compile('.+action=\"(.+)\".+')
		action_url=regex.search(responseTxt)
		if action_url == None:
			dm.logger.error("failed to return a redirect URL for PUT", responseTxt)
			return jsonify({'success': False, 'error': responseTxt})
		url = action_url.group(1)
		parsed_url = re.search('(http://.*)\?httpstoken=(.*)&httpsauthz=(.*)', url)
		dest = parsed_url.group(1)
		httpstoken = parsed_url.group(2)
		httpsauthz = parsed_url.group(3)
		resp = {'dest' : dest, 'httpstoken' : httpstoken, 'httpsauthz' : httpsauthz, 'put_url' : url}
		print resp
		dm.logger.info("redirect URL for PUT upload", url)
		return jsonify(resp)
		#return json.dumps(resp)


@dm.route("/putdone/<se>/<path:path>")
#@dm.route("/putdone/<vo>/<filename>/<se>/<path:path>")
#def putdone(vo, filename, se, path):
def putdone(se, path, vo="", filename=""):

	print "sono qui"
	print "vo: ", vo
	print "se: ", se
	print "path: ", path
	print "filename: ", filename

	dpmtoken = request.args.get('dpmtoken','');
	print "sono in putdone", dpmtoken
	if not dpmtoken:
		return jsonify({'success': False, 'error': "No dpmtoken provided"});

	if vo == "":
		vo = "vo.indicate-project.eu"

	proxy = get_proxy(vo)
	print "dopo proxy"

	if filename:
		path = "/%s/%s?metacmd=putdone&dpmtoken=%s" % (path, filename, dpmtoken)
	else:
		path = "/%s?metacmd=putdone&dpmtoken=%s" % (path, dpmtoken)
	print "se: ", se
	print "path: ", path
	print "dpmtoken:", dpmtoken
	conn = httplib.HTTPSConnection(se, cert_file=proxy, key_file=proxy)
	try:
		conn.request("GET", path)
	except Exception, e:
		#return HttpResponseNotFound("Network error: %s" % e)
		abort(404)

	resp = conn.getresponse()
	#print resp.status
	#print resp.reason
	#print resp.getheaders()
	responseTxt = resp.read()
	#print responseTxt
	return jsonify({'success': True, 'response': resp.reason});

@dm.route('/warc/extract/<vo>/<se>/<path:path>/<offset>')
def warc(vo, se, path, offset):

	print "WarcExtract"
	print "vo:", vo
	print "se:", se
	print "path:", path
	print "offset", offset

	proxy = get_proxy(vo)

	local_filename = "/tmp/" + path.split('/')[-1]
	print "local_filename:",  local_filename
	url = "https://" + se + "/" + path
	print "url:", url
	r = requests.get(url, stream=True, cert=proxy, verify=False)
	with open(local_filename, 'wb') as f:
		for chunk in r.iter_content(chunk_size=1024):
			if chunk: # filter out keep-alive new chunks
				f.write(chunk)
				f.flush()
	print "write completed"
	print local_filename, offset
	#print warcpayload.dump_payload_from_file
	#print dir(warcpayload.dump_payload_from_file)
	#warcpayload.dump_payload_from_file(local_filename, offset, None, '/tmp/warc_dump')
	os.system("/opt/python27/bin/warcpayload " + local_filename + ":" + offset + " > /tmp/warc_dump")
	print "file extracted"
	#print "payload:", payload
	#out = open('/tmp/data', 'wb')
	#out.write(payload)

	return send_from_directory('/tmp','warc_dump')


@dm.route('/sign_s3/')
def sign_s3():
	AWS_ACCESS_KEY = 'AKIAJTM37DDJONDPAT5Q'
	AWS_SECRET_KEY = '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'
	S3_BUCKET = 'etnatraining'

	object_name = request.args.get('s3_object_name')
	mime_type = request.args.get('s3_object_type')

	expires = int(time.time()+60)
	amz_headers = "x-amz-acl:public-read"

	put_request = "PUT\n\n%s\n%d\n%s\n/%s/%s" % (mime_type, expires, amz_headers, S3_BUCKET, object_name)

	signature = base64.encodestring(hmac.new(AWS_SECRET_KEY, put_request, sha).digest())

	url = 'https://%s.s3.amazonaws.com/%s' % (S3_BUCKET, object_name)

	return json.dumps({
		'signed_request': '%s?AWSAccessKeyId=%s&Expires=%d&Signature=%s' % (url, AWS_ACCESS_KEY, expires, signature),
		 'url': url
	})

@dm.route('/cloud/<host>/<path:path>', methods=['GET','PUT'])
def swift(host, path):
	seconds = 120
	expires = int(time.time() + int(seconds))
	if not path.startswith('/'):
		path = '/' + path
	parts = path.split('/', 4)
	print "path=", path
	print "parts=", parts
	# Must be five parts, ['', 'v1', 'a', 'c', 'o'], must be a v1 request, have
    	# account, container, and object values, and the object value can't just
    	# have '/'s.
	if len(parts) != 5 or parts[0] or parts[1] != 'v1' or not parts[2] or \
	    not parts[3] or not parts[4].strip('/'):
		response = jsonify({"error": 'WARNING: "%s" does not refer to an object (e.g. /v1/account/container/object)' % path})
    		response.status_code = 400
    		return response
	print "path corretto"
	account = parts[2]
	keys = {
		"AUTH_51b2f4e508144fa5b0c28f02b1618bfd":"correcthorsebatterystaple",
		"AUTH_3729798f1d494dcba22abe9763c22258":"4paxXm3tar94T62oGrlQSi5bE4o5mcA1"
	}
	try:
		print "(method, key, expires, path)=", request.method, keys[account], expires, path
		sig = hmac.new(keys[account], '%s\n%s\n%s' % (request.method, expires, path), sha1).hexdigest()
		print "signature", sig
		return jsonify({"url": 'http://%s:8080%s?temp_url_sig=%s&temp_url_expires=%s' % (host, path, sig, expires)})
	except Exception, e:
		response = jsonify({"error": "no valid key found for the account %s" % account})
		response.status_code = 400
		return response


def get_proxy(vo):
	disable_voms = "true"
	if vo == "vo.indicate-project.eu":
		proxy_file = '/tmp/indicate_proxy'
		robot_serial = '26467'
		certificate_md5 = '876149964d57df2310eb3d398f905749'
		attribute = '/vo.indicate-project.eu'
	elif vo == "vo.aginfra.eu":
		robot_serial = '25667'
		attribute = '/vo.aginfra.eu'
		certificate_md5 = '62b53afcb320386d6ad938d3d2fdfbfc'
		proxy_file = '/tmp/aginfra_proxy'
	elif vo == "vo.earthserver.eu":
		robot_serial = "25668"
		proxy_file = '/tmp/earthserver_proxy'
		certificate_md5 = '36beeec99546392a0fd6692242fef938'
		attribute = '/vo.earthserver.eu'
	elif vo == "vo.dch-rp.eu" or vo == 'vo.indicate-project.eu':
		robot_serial = '26581'
		proxy_file = '/tmp/dchrp_proxy'
		certificate_md5 = '876149964d57df2310eb3d398f905749'
		attribute='/vo.dch-rp.eu'
	elif vo == "vo.eu-decide.eu":
		robot_serial = '28895'
		proxy_file = '/tmp/decide_proxy'
		certificate_md5 = '2ce14167e631d8bd1fb4a5f2b86602e0'
		attribute='/vo.eu-decide.eu'
		disable_voms = "false"
	elif vo == "eumed" or vo == 'see':
		robot_serial = '27696'
		proxy_file = '/tmp/eumed_proxy'
		certificate_md5 = 'bc681e2bd4c3ace2a4c54907ea0c379b'
		attribute='/eumed'
	elif vo == "prod.vo.eu-eela.eu":
                robot_serial = '31355'
                proxy_file = '/tmp/eela_proxy'
                certificate_md5 = '43ddf806454eb55ea32f729c33cc1f07'
                attribute='/prod.vo.eu-eela.eu'
		disable_voms = "false"
	elif vo == "vo.progettovespa.it":
                robot_serial = '31782'
                proxy_file = '/tmp/vespa_proxy'
                certificate_md5 = '2ce14167e631d8bd1fb4a5f2b86602e0'
                attribute='/vo.progettovespa.it'
                disable_voms = "false"
	else:
		robot_serial = '25207'
		proxy_file = '/tmp/cataniasg_proxy'
		certificate_md5 = '332576f78a4fe70a52048043e90cd11f'
		attribute = '/' + vo

	#print request.environ
	##print "call to get_proxy"
	dm.logger.info("Retrieving a proxy from etokenserver.ct.infn.it for VO '%s'", vo)
	#etokenserver = "myproxy.ct.infn.it"
	#server_url = "http://myproxy.ct.infn.it:8082/eTokenServer/eToken/%s?voms=%s:%s&proxy-renewal=false&disable-voms-proxy=true" % (certificate_serial, vo, attribute)
	server_url = "http://etokenserver.ct.infn.it:8082/eTokenServer/eToken/%s?voms=%s:%s&proxy-renewal=false&disable-voms-proxy=%s&rfc-proxy=true&cn-label=eToken:Empty" % (certificate_md5, vo, attribute, disable_voms)
	print "PROXY REQUEST: ", server_url
	f = urllib.urlopen(server_url)
	proxy = open(proxy_file, "w");
	proxy.write(f.read())
	f.close()
	proxy.close()
	os.chmod(proxy_file, 0600)
	dm.logger.info("Proxy stored in '%s'", proxy_file)
	return proxy_file





if __name__ == "__main__":
	# Configure logs
	print "set log handler"
	handler = logging.FileHandler('/tmp/glibrary.log')
	handler.setLevel(logging.DEBUG)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	dm.logger.addHandler(handler)
	print "log handler set"
	dm.run(host='0.0.0.0', port=8000, debug=True)

#opener = robot_init()
