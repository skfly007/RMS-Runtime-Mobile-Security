

let http=require("http");
var express=require("express");
var sio=require("socket.io");
var app=express();
var server=http.createServer(app);
server.listen(1337);
var socket=sio.listen(server);