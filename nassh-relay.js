/**
 * @author Clemens Fruhwirth <clemens@endorphin.org>
 *
 * This is a relay implementation for the Chrome Native Client port of
 * Secure Shell. You can use this relay when NaSSH can't connect to
 * your SSH host directly.
 *
 * +-----------------+
 * | Relay selection |
 * +-----------------+
 *         ^   |
 * backend |   | relay-host/port
 *  host   |   v
 * +--------------+                        +-------+         +-------------+
 * |   Frontend   | --HTTP /proxy--------->| Relay |         | SSH backend |
 * |              | --WebSocket /connect-->|       | <-TCP-> |             |
 * +--------------+                        +-------+         +-------------+
 * 
 * In this diagram and below, the frontend is NaSSH.
 *
 * RELAY SELECTION PROTOCOL
 * ========================
 * 
 * In NaSSH, the user can configure relay options. By supplying
 * --proxy-host and --proxy-port the user points the frontend to the
 * relay selection.  Upon connect, the frontend GETs
 * http://proxy-host:proxy-port/cookie. This handler takes two query
 * parameters:
 * - ext: chrome extension identifier
 * - path: deep-link to a resource in the extension that handles the
 *         following callback.
 * 
 * When done with handling the request, the relay server redirects to
 *   chrome-extension://<ext>/<path>#<user>@<relay-host>:<relay-port>,
 * where
 *   ext is the query parameter ext
 *   path is the query parameter path
 *   user is ignored
 *   relay-host, relay-port, the host/port of the selected relay.
 * 
 * Implementation: Our /cookie handler just redirects right away back
 * to ourselves without guiding the user through a web flow of some
 * sort. You might want to add authentication, or a geographical relay
 * server selector to that flow.
 *
 * RELAY PROTOCOL 
 * ==============
 * After the frontend got a relay host, it GETs
 *   http://relay-host:relay-port/proxy?host=ssh-host&port=ssh-port.
 * During that GET request, the relay establishes a connection to the
 * backend on ssh-host/ssh-port, and once this is done, returns a
 * session ID to the frontend as request body.
 *
 * From here on, frontend assumes an established backend connection and
 * starts a protocol that is able to handle retransmissions. With the
 * session ID, the frontend issues a websocket upgrade to
 * http://relay-host:relay-port/connect?<querystring> endpoint. 
 * 
 * Before we talk about the querystring, let's talk about the protocol
 * that follows within the websocket conversation. Each websocket
 * frame is a binary frame. UTF8 frames are not used.
 * 
 * 0 +------------+
 *   | Ack offset |
 * 4 +------------+   
 *   | payload    |
 *   |            |
 *   :            :
 *   .            .
 *
 * When the frontend wants to push messages to the relay, does so in a
 * binary frame. It also pigbacks onto this the bytestream offset it
 * has received as incoming. This numbers serves as a confirmation to
 * the relay. The relay speaks exactly the same protocol, and when it
 * pushes data to frontend via a binary frame message, it also
 * confirms to the frontend the bytestream offset of the stream coming
 * from the frontend. We also call the offset, ack offset, or just
 * ack.
 *
 * Both sides need to keep a retransmission buffer, and each can only
 * discard bytes which have an absolute position in the bytestream
 * that is smaller then the ack offset received from the peer. There
 * are no frames related to actually initiating a retransmission. What
 * happens in practise is that the websocket connection is dropped,
 * and the frontend reconnects to the /connect endpoint.
 *
 * Now we can talk about the querystring in /connect.
 *   sid: backend session identifier as received by /proxy
 *   ack: number of bytes received by frontend from the relay
 *   pos: position in the stream sent from the frontend to the relay
 *
 * The ack number in the querystring has the same semantic as the ack
 * offset in a websocket frame.
 * 
 * The pos part tells the relay what frontend is about to send. If the
 * relay has already seen those bytes, it just doesn't forward them to
 * the backend.
 *
 * License: AGPL-v3
 */

var http = require("http"),
    util = require("util"),
    url  = require("url"),
    net  = require("net"),
    uuid = require("node-uuid"),
    WebSocketServer = require("websocket").server;

var sessions = {}

var log = function(str) {
    console.log((new Date()) + " " + str);
}

if(process.argv.length < 3 || process.argv.length > 4) {
    console.log("Usage: nassh-relay.js <bind-port> [external-redirect]")
    process.exit(1)
}

var port = parseInt(process.argv[2])
var externalRedirect = null
if(process.argv.length == 4) {
    externalRedirect = process.argv[3]
}

// bsplice(index) is most of the time equal to splice(-index), so it
// takes the tail portion of a Buffer. However, as there is no minus 0
// but just 0, splice(-0) doesn't return an empty buffer, but the
// complete buffer. As we would like -0 semantics, we correct for that
// corner case, here and don't have to do special case checking at the
// caller.
Buffer.prototype.bslice = function(index) {
    if(index > this.length || index < 0)
	throw new Error("Trying to splice an array at index " + (this.length - index));
    if(index == 0)
	return new Buffer(0);

    return this.slice(-index);
}

var friendlyBufferRelease = 256*256*16; // 1MB

var Session = function(host, port, callbackFail, callbackSuccess) {

    var ses = this;

    ses.sid = uuid.v4();
    ses.host = host;
    ses.port = port;

    // Socket to backend
    ses.backendSocket = net.Socket();
    ses.backendSocket.on("data", function(buf) {
	// Send to frontend
	ses.sendFragment(buf);
	// .. and add to retransmission buffer
	ses.B2FUnacked = Buffer.concat([ses.B2FUnacked, buf]);
    });

    ses.backendSocket.on("error", callbackFail);
    ses.backendSocket.on("connect", function() {
	ses.backendSocket.removeListener("error", callbackFail)
	callbackSuccess();
    });
    ses.backendSocket.on("close", function(has_error) {
	// this is called also for errors.
	sessions[ses.sid] = null;
	if(ses.frontendCon) {
	    ses.frontendCon.closeProtocol();
	}
    });
    ses.backendSocket.connect(ses.port, ses.host);

    // Retransmission buffer
    ses.B2FUnacked = new Buffer(0);

    // Current websocket connection to frontend.
    // Can be null, when no frontend is connected.
    ses.frontendCon = null;
}

Session.prototype.log = function(str) {
    log("[" + this.sid + "] " + str)
}

// Sends a fragment to the current connection
Session.prototype.sendFragment = function(fragment) {
    if(this.frontendCon) {
	var headerBuffer = new Buffer(4);
	headerBuffer.writeInt32BE(
	    // We have to take the minimum here, as we don't want
	    // to irritate the frontend by sending an ack pointer
	    // that's ahead of its bytestream.
	    Math.min(this.backendSocket.bytesWritten,
		     this.frontendCon.pos),
	    0);
	this.frontendCon.sendBytes(Buffer.concat([headerBuffer, fragment]));
    }
}

// Process an ack from the frontend. Returns false on failures.
Session.prototype.shrinkBuffer = function(ack) {
    if(ack > this.backendSocket.bytesRead) {
	// If ack bigger than what we have sent, then we are not
	// sure what has happen.
	this.log("Buffer shrink failed: Ack number ahead.")
	return false;
    }
    if(ack < (this.backendSocket.bytesRead - this.B2FUnacked.length)) {
	// If ack is smaller than what we have in the buffer, then the
	// frontend is rerequesting a bytestream segment it already
	// has acked.
	this.log("Buffer shrink failed: Ack number behind our buffer.")
	return false;
    }
    this.B2FUnacked = this.B2FUnacked.bslice(this.backendSocket.bytesRead - ack);
    return true;
}

// Adopts the given frontend connection as current websocket connection.
Session.prototype.adopt = function(frontendCon, ack, pos) {
    var ses = this

    // Do we have another frontend connection? Close it.
    if(ses.frontendCon) {
	ses.frontendCon.closeProtocol();
    }
    frontendCon.on("close", function(reasonCode, description) {
	if(ses.frontendCon == frontendCon) {
	    ses.frontendCon = null;
	}
        ses.log("Peer " + frontendCon.remoteAddress + " disconnected.");
    });
    frontendCon.on("message", function(message) {
	// Whenever we see a "message", this must be the currently
	// adopted frontend. If we adopted another frontend
	// connection, we have called close() via closeProtocol() on
	// the old connection and calling close() guarantees that no
	// "message" will be emitted afterwards.
	if (message.type === "utf8") {
	    // utf8 isn't used by the frontend. Panic
	    frontendCon.closeProtocol();
	}
	else if (message.type === "binary") {
	    frontendCon.pos += message.binaryData.length - 4;
	    
	    // Forward unseen data from frontend to backend
	    // connection.
	    var unseenPayload = message.binaryData.bslice(
		Math.max(frontendCon.pos - ses.backendSocket.bytesWritten, 0));
	    
	    ses.backendSocket.write(unseenPayload);
	    
	    // We received an updated ack pointer from the frontend.
	    // We might be able to shrink our buffers in response.
	    ok = ses.shrinkBuffer(message.binaryData.readInt32BE(0));
	    if(!ok) {
		frontendCon.emit("close");
		return;
	    }
	    
	    // If the frontend has been sending us data, but we
	    // haven't replied for a while, the frontend doesn't know
	    // that we received that data. Let's be friendly, and from
	    // time to time signal our state with an empty block.
	    if(ses.backendSocket.bytesWritten - frontendCon.pos > friendlyBufferRelease) {
		ses.sendFragment(new Buffer(0));
	    }
 	}
    });
    
    if(pos > ses.backendSocket.bytesWritten) {
	// If this is bigger than what we have seen, we have a gap in
	// receiving data. Close the connection. It's unrecoverable.
	ses.log("Pos number error.")
	frontend.closeProtocol();
	return;
    }

    // This is the offset in the frontend->backend bytestream from
    // which on the frontend is going to send data fragments. In a
    // fresh connection this should be 0. In a connection resume, this
    // should be the last offset the frontend got an ack for.
    frontendCon.pos = pos
    
    ok = ses.shrinkBuffer(ack)
    if(!ok) {
	frontendCon.closeProtocol();
	return;
    }
    
    ses.frontendCon = frontendCon;

    ses.log("Adopted new frontend from from " + frontendCon.remoteAddress)
    // We shrunk the buffer before so we know that the
    // B2FUnacked really contains just unacked bytes.
    ses.sendFragment(ses.B2FUnacked)
}


var httpServer = http.createServer(function (request, response) {
    request.resourceURL = url.parse(request.url, true);
    if(request.resourceURL.pathname == "/cookie") {
	if(request.resourceURL.query
	   && request.resourceURL.query.ext
	   && request.resourceURL.query.path) {
	    // We redirect back to ourselves without asking much
	    // questions. If we don't know ourselves that well, we use
	    // externalRedirect to find ourselves.
	    response.writeHead(302, {
		"Location": util.format("chrome-extension://%s/%s#ignored@%s",
					request.resourceURL.query.ext,
					request.resourceURL.query.path,
					externalRedirect?externalRedirect:request.headers.host)
	    });
	    response.end();
	} else {
	    response.writeHead(400, { "Content-Type": "text/plain" });
	    response.end("Request for /cookie needs a query string that sets ext to the" +
			 "chrome-extension identifier and a path for redirection.");
	}
    } else if(request.resourceURL.pathname == "/proxy") {
	if(request.resourceURL.query.host && request.resourceURL.query.port) {
	    var commonHeader = {"Content-Type": "text/plain",
				"Access-Control-Allow-Origin" :  request.headers.origin,
				"Access-Control-Allow-Credentials": "true"
			       };
	    var ses = new Session(
		request.resourceURL.query.host,
		request.resourceURL.query.port, 
		// fail callback
		function() {
		    response.writeHead(502, commonHeader);
		    response.end();
		},
		// success callback
		function() {
		    ses.log(util.format("Forwarding client from %s to %s:%s", 
					request.connection.remoteAddress,
					request.resourceURL.query.host,
					request.resourceURL.query.port));
		    response.writeHead(200, commonHeader);
		    sessions[ses.sid] = ses;
		    response.end(ses.sid);
		})
	} else {
	    response.writeHead(400, { "Content-type": "text/plain"});
	    response.end("Request for /proxy needs a query string that sets host and path for relay.");
	}
    } else {
	log("Can't find handler: " + request.url);
	response.writeHead(404, { "Content-type": "text/plain"});
	response.end("Unknown endpoint");
    }
});

httpServer.listen(port);

wsServer = new WebSocketServer({
    httpServer: httpServer,
    autoAcceptConnections: false
});

wsServer.on("request", function(request) {
    // We always accept the upgrade, as NaSSH does not understand
    // websocket upgrade rejections as a no and keeps retrying.
    var frontendCon = request.accept(null, request.origin);

    // Signal a close within the relay protocol by writing a negative
    // ack number. Then close the underlying websocket. That makes
    // NaSSH accept that the connection is broken and make it not
    // retry.
    frontendCon.closeProtocol = function() {
	var headerBuffer = new Buffer(4);
	headerBuffer.writeInt32BE(-1, 0);
	frontendCon.sendBytes(headerBuffer);
	frontendCon.close();
    };

    if(request.resourceURL.pathname != "/connect") {
	log("Websocket connect to unknown endpoint " + request.resourceURL.pathname);
	frontendCon.closeProtocol();
    }

    if(!(request.resourceURL.query
	 && request.resourceURL.query.sid)) {
	log("Session id missing from " + frontendCon.remoteAddress);
	frontendCon.closeProtocol();
	return;
    }

    var ses = sessions[request.resourceURL.query.sid];

    if(typeof(ses) === "undefined") {
	log("Unknown session id from " + frontendCon.remoteAddress);
	frontendCon.closeProtocol();
	return;
    }
    ses.adopt(frontendCon,
	      parseInt(request.resourceURL.query.ack),
	      parseInt(request.resourceURL.query.pos));
});

log("Relay running on http://localhost:" + port + "/");
