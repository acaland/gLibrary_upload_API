from flask import Flask, request, redirect
import json, re
from M2Crypto import m2urllib2
from M2Crypto import m2, SSL, Engine

dm = Flask(__name__)

@dm.route("/hello")
def hello():
	if not request.environ.has_key('SSL_CLIENT_S_DN'):
		return "you need to be authenticated"
	else:
		return request.environ['SSL_CLIENT_S_DN']	

@dm.route("/dm/<se>/<path:path>")
def download(se, path):
	print se
	print path
	opener = robot_init()
	info = {}
	info['se'] = se
	info['path'] = path
	print request.args.get('pippo','')
	info['robot'] = request.args.get('robot','') 
	info['voms'] = request.args.get('voms','')
        
	link = "https://%s/%s?authip=%s" % (se, path, request.environ['REMOTE_ADDR'])
        print "download link: ", link
        req = m2urllib2.Request(str(link))
	redirect_url = opener.open(req)
        #redirect_url = u.geturl()

        print redirect_url

        #pk.finish()
        #Engine.cleanup()

        return redirect(redirect_url)

@dm.route("/dm/upload/<filename>/<se>/<path:path>")
def upload(filename, se, path):
	opener = robot_init()
	
	link = "https://%s/%s?metacmd=post&filename=%s&metaopt=755&authip=%s" % (se, path, filename, request.environ['REMOTE_ADDR'])
	print "request url: ", link
	req = m2urllib2.Request(str(link))
        connect = opener.open(req)
	resp = connect.read()
	connect.close()
	regex = re.compile('.+action=\"(.+)\".+')
	action_url=regex.search(resp)
	url = action_url.group(1)
	parsed_url = re.search('(http://.*)\?httpstoken=(.*)&httpsauthz=(.*)', url)
	dest = parsed_url.group(1)
	httpstoken = parsed_url.group(2)
	httpsauthz = parsed_url.group(3)
	resp = {'dest' : dest, 'httpstoken' : httpstoken, 'httpsauthz' : httpsauthz, 'post_url' : url}
	print resp
	return json.dumps(resp)
	


#if __name__ == "__main__":
def robot_init():
	
	e = Engine.load_dynamic_engine("pkcs11", "/usr/local/lib/engine_pkcs11.so")

        pk = Engine.Engine("pkcs11")
        pk.ctrl_cmd_string("MODULE_PATH", "/usr/lib/libeTPkcs11.so")
        ret = pk.init()

        print "Loading certificate DeRoberto"
        cert = e.load_certificate("30354530383037334131344144353636")
        print "Loading key ..."
        key = e.load_private_key("30354530383037334131344144353636", "indicate#2011")

	ctx = SSL.Context("sslv23")
        ctx.set_cipher_list("HIGH:!aNULL:!eNULL:@STRENGTH")
        ctx.set_session_id_ctx("foobar")
        m2.ssl_ctx_use_x509(ctx.ctx, cert.x509)
        m2.ssl_ctx_use_pkey_privkey(ctx.ctx, key.pkey)

	class SmartRedirectHandler(m2urllib2.HTTPRedirectHandler):
                def http_error_302(self, req, fp, code, msg, headers):
                        redirect = headers['Location']
                        return redirect

        opener = m2urllib2.build_opener(ctx, SmartRedirectHandler())
	return opener
	
    	#app.run(host='0.0.0.0', debug=True)

#opener = robot_init()
