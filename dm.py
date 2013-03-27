from flask import Flask, request, redirect, abort, jsonify
import json, re, urllib, httplib, os

dm = Flask(__name__)

@dm.route("/hello")
def hello():
	if not request.environ.has_key('SSL_CLIENT_S_DN'):
		return "you need to be authenticated"
	else:
		return request.environ['SSL_CLIENT_S_DN']	

@dm.route("/<vo>/<se>/<path:path>")
def download(vo, se, path):
	print vo
	if vo == "vo.indicate-project.eu":
		proxy = '/tmp/indicate_proxy'
		robot_serial = '26467'
		attribute = '/vo.indicate-project.eu'
	elif vo == "vo.aginfra.eu":
		robot_serial = '25667'
		attribute = '/vo.aginfra.eu'
		proxy = '/tmp/aginfra_proxy'
	elif vo == "vo.earthserver.eu":
		robot_serial = "25668"
		proxy = '/tmp/earthserver_proxy'
		attribute = '/vo.earthserver.eu'
	elif vo == "vo.dch-rp.eu":
		robot_serial = '26581'
		proxy = '/tmp/dchrp_proxy'
		attribute='/vo.dch-rp.eu'
	else:
		robot_serial = '25207'
		proxy = '/tmp/cataniasg_proxy'
		attribute = '/' + vo
		
	get_proxy(robot_serial, vo, attribute, proxy)
	
	info = {}
	info['se'] = se
	info['path'] = path
	print request.args.get('pippo','')
	info['robot'] = request.args.get('robot_serial','') 
	info['voms'] = request.args.get('voms','')
	#link = "https://%s/%s?authip=%s" % (se, path, request.environ['REMOTE_ADDR'])
	#print "download link: ", link
    
    #print request.META['REMOTE_ADDR']
	#print request.META['HTTP_X_FORWARDED_FOR']
	#print request.META['HTTP_X_FORWARDED_HOST']
	
	path = "/%s?authip=%s" % (path, request.environ['REMOTE_ADDR'])
	print se
	print path
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
	redirect_url = resp.getheader("location")
	print redirect_url
	if redirect_url == None:
		output = resp.read()
		print output
		conn.close()
		abort(404)
		#return HttpResponseNotFound("replica (%s) not found<br>%s" % (link, output))
	conn.close()
	return redirect(redirect_url)
	
    
@dm.route("/upload/<vo>/<filename>/<se>/<path:path>")
def upload(vo, filename, se, path):
	if vo == "vo.indicate-project.eu":
		proxy = '/tmp/indicate_proxy'
		robot_serial = '26467'
		attribute = '/vo.indicate-project.eu'
	elif vo == "vo.aginfra.eu":
		robot_serial = '25667'
		attribute = '/vo.aginfra.eu'
		proxy = '/tmp/aginfra_proxy'
	elif vo == "vo.earthserver.eu":
		robot_serial = "25668"
		proxy = '/tmp/earthserver_proxy'
		attribute = '/vo.earthserver.eu'
	elif vo == "vo.dch-rp.eu":
		robot_serial = '26581'
		proxy = '/tmp/dchrp_proxy'
		attribute='/vo.dch-rp.eu'
	else:
		robot_serial = '25207'
		proxy = '/tmp/cataniasg_proxy'
		attribute = '/' + vo
		
	get_proxy(robot_serial, vo, attribute, proxy)

	
	path = "/%s?metacmd=post&filename=%s&metaopt=755&authip=%s" % (path, filename, request.environ['REMOTE_ADDR'])
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

@dm.route("/putdone/<vo>/<filename>/<se>/<path:path>")	
def putdone(vo, filename, se, path):
	
	dpmtoken = request.args.get('dpmtoken','');
	print "sono in putdone", dpmtoken
	if not dpmtoken:
		return jsonify({'success': False, 'error': "No dpmtoken provided"});
	
	if vo == "vo.indicate-project.eu":
		proxy = '/tmp/indicate_proxy'
		robot_serial = '26467'
		attribute = '/vo.indicate-project.eu'
	elif vo == "vo.aginfra.eu":
		robot_serial = '25667'
		attribute = '/vo.aginfra.eu'
		proxy = '/tmp/aginfra_proxy'
	elif vo == "vo.earthserver.eu":
		robot_serial = "25668"
		proxy = '/tmp/earthserver_proxy'
		attribute = '/vo.earthserver.eu'
	elif vo == "vo.dch-rp.eu":
		robot_serial = '26581'
		proxy = '/tmp/dchrp_proxy'
		attribute='/vo.dch-rp.eu'
	else:
		robot_serial = '25207'
		proxy = '/tmp/cataniasg_proxy'
		attribute = '/' + vo
		
	get_proxy(robot_serial, vo, attribute, proxy)
	print "dopo proxy"
	
	path = "/%s/%s?metacmd=putdone&dpmtoken=%s" % (path, filename, dpmtoken)
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
	return jsonify({'success': True, 'response': resp.reason})
	
	
	
		
	


def get_proxy(certificate_serial, vo, attribute, proxy_file):

    #print request.environ
    print "call to get_proxy"
    etokenserver = "myproxy.ct.infn.it"

    server_url = "http://myproxy.ct.infn.it:8082/eTokenServer/eToken/%s?voms=%s:%s&proxy-renewal=false&disable-voms-proxy=true" % (certificate_serial, vo, attribute)
    print server_url
    f = urllib.urlopen(server_url)
    proxy = open(proxy_file, "w");
    proxy.write(f.read())
    f.close()
    proxy.close()
    os.chmod(proxy_file, 0600)





if __name__ == "__main__":
	dm.run(host='0.0.0.0', port=8000, debug=True)

#opener = robot_init()
