// load the http module
var http = require('http');

// configure our HTTP server
var server = http.createServer(function (request, response) {
  response.writeHead(200, {"Content-Type": "text/html"});
  response.end("<H2>Hello Docker - Node App running in container!! \n</H2>");
});

// listen on localhost:8009
server.listen(8009);
console.log("Server started & listening on port 8000 :  http://127.0.0.1:8009/");
