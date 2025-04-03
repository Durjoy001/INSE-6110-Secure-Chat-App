const express = require("express")
const socketio = require("socket.io")
const http = require("http")
const bcrypt = require('bcrypt');
const saltRounds = 10;
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 4000

const Chat = require("./routers/Chat")

const app = express()

const server = http.createServer(app)

const io = socketio(server,{cors: {
      origin: "http://localhost:3000",
      methods: ["GET", "POST"],
      credentials: true
}})

//DataBase
const db = [
      {
            id:"alice1",
            name:"Alice",
            pass:"$2b$10$Vwtp6DsdbvY6xeAoUiR2QO/0/hwYIutjJDrnK.000A05d6sOAXN1C",
            online:false,
            token:"",
            socketId:"",
            certificate: null
      },
      {
            id:"bob1",
            name:"Bob",
            pass:"$2b$10$Vwtp6DsdbvY6xeAoUiR2QO/0/hwYIutjJDrnK.000A05d6sOAXN1C",
            online:false,
            token:"",
            socketId:"",
            certificate: null
      },
      {
            id:"user3",
            name:"User3",
            pass:"$2b$10$Vwtp6DsdbvY6xeAoUiR2QO/0/hwYIutjJDrnK.000A05d6sOAXN1C",
            online:false,
            token:"",
            socketId:"",
            certificate: null
      },
      {
            id:"user4",
            name:"User4",
            pass:"$2b$10$Vwtp6DsdbvY6xeAoUiR2QO/0/hwYIutjJDrnK.000A05d6sOAXN1C",
            online:false,
            token:"",
            socketId:"",
            certificate: null
      }
]

var Mesajlar = []

io.on("connection",(socket)=>{
      socket.on("login",data=>{
            const user = db.find((user) => user.name.toLowerCase() === data.name.toLowerCase());

            if(user){
                  bcrypt.compare(data.pass, user.pass, function(err, result) {
                        if (result) {
                              bcrypt.hash(user.id, saltRounds, function(err, hash) {
                                    console.log("Login successful for user:", user.name);
                                    socket.emit("login",{
                                          auth: true,
                                          token: hash,
                                          name: user.name  // Include username in response
                                    });
                                    user.token = hash;
                              });
                        }
                        else {
                              console.log("Login failed: Invalid password for user:", data.name);
                              socket.emit("login",{auth: false});
                        }
                  });
            }
            else{
                  console.log("Login failed: User not found:", data.name);
                  socket.emit("login",{auth: false});
            }
      })

      socket.on("auth",async(token)=>{
            const user = db.find((user) => user.token === token);

            if(user){
                  var users = []
                  user.online = true
                  user.socketId = socket.id
                  db.map((item)=>users.push({name:item.name,online:item.online,id:item.id}))
                  await socket.emit("auth",{auth:true,name:user.name,id:user.id,users:users})
                  await socket.broadcast.emit("online",users)

                  var temp = []
                  Mesajlar.map(async(item)=>{
                        if(item.kime === user.name){
                              if(item.lobbymi){
                                    await io.sockets.to(socket.id).emit("IncomingMessage",{
                                          mesaj: item.mesaj,
                                          name: item.kimden,
                                          isLobby: true,
                                          signature: item.signature,
                                          senderPublicKey: item.senderPublicKey
                                    })
                              }
                              else{
                                    await io.sockets.to(socket.id).emit("IncomingMessage",{
                                          mesaj: item.mesaj,
                                          name: item.kimden,
                                          isLobby: false,
                                          signature: item.signature,
                                          senderPublicKey: item.senderPublicKey
                                    })
                              }
                        }
                        else{
                              temp.push(item)
                        }
                  })

                  Mesajlar = temp
            }
            else{
                  await socket.emit("auth",{auth:false})
            }  
      })

      // Handle certificate storage
      socket.on("storeCertificate", (data, callback) => {
            console.log("Received certificate storage request");
            console.log("Username:", data.username);
            console.log("Certificate data:", JSON.stringify(data.certificate, null, 2));
            
            // Validate input data
            if (!data.username || !data.certificate) {
                  console.error("Invalid certificate data: missing username or certificate");
                  callback(false);
                  return;
            }
            
            const user = db.find((user) => user.name.toLowerCase() === data.username.toLowerCase());
            console.log("Found user:", user ? user.name : "No user found");
            
            if (!user) {
                  console.error("User not found for certificate storage:", data.username);
                  console.log("Available users:", db.map(u => u.name));
                  callback(false);
                  return;
            }
            
            try {
                  // Store in memory
                  user.certificate = data.certificate;
                  console.log("Certificate stored in memory for user:", data.username);
                  
                  // Create certificates directory if it doesn't exist
                  const certDir = path.join(__dirname, 'certificates');
                  console.log("Certificate directory path:", certDir);
                  
                  if (!fs.existsSync(certDir)) {
                        fs.mkdirSync(certDir, { recursive: true });
                        console.log("Created certificates directory");
                  }
                  
                  // Store certificate in file system
                  const certPath = path.join(certDir, `${user.name}_cert.pem`);
                  console.log("Certificate file path:", certPath);
                  
                  // Ensure the certificate data is properly formatted
                  const certData = {
                        subject: data.certificate.subject,
                        publicKeys: data.certificate.publicKeys,
                        issuedAt: data.certificate.issuedAt,
                        expiresAt: data.certificate.expiresAt
                  };
                  
                  // Validate certificate data
                  if (!certData.subject || !certData.publicKeys || !certData.issuedAt || !certData.expiresAt) {
                        console.error("Invalid certificate format: missing required fields");
                        callback(false);
                        return;
                  }
                  
                  // Validate public keys
                  if (!certData.publicKeys.encryptionPublicKey || !certData.publicKeys.signingPublicKey) {
                        console.error("Invalid certificate format: missing encryption or signing public key");
                        callback(false);
                        return;
                  }
                  
                  fs.writeFileSync(certPath, JSON.stringify(certData, null, 2));
                  console.log("Certificate saved to file successfully");
                  
                  // Verify the file was created and is readable
                  if (fs.existsSync(certPath)) {
                        const fileContent = fs.readFileSync(certPath, 'utf8');
                        console.log("Verified certificate file exists and is readable");
                        callback(true);
                  } else {
                        console.error("Certificate file was not created");
                        callback(false);
                  }
            } catch (error) {
                  console.error("Error storing certificate:", error);
                  console.error("Error stack:", error.stack);
                  callback(false);
            }
      });

      // Handle certificate retrieval
      socket.on("getUserCertificate", (data, callback) => {
            console.log("Retrieving certificate for user:", data.username);
            const user = db.find((user) => user.name.toLowerCase() === data.username.toLowerCase());
            
            if (user && user.certificate) {
                  console.log("Certificate found for user:", data.username);
                  callback(user.certificate);
            } else {
                  console.error("No certificate found for user:", data.username);
                  // Try to load from file if not in memory
                  const certPath = path.join(__dirname, 'certificates', `${data.username}_cert.pem`);
                  if (fs.existsSync(certPath)) {
                        try {
                              const certData = JSON.parse(fs.readFileSync(certPath, 'utf8'));
                              user.certificate = certData;
                              console.log("Certificate loaded from file for user:", data.username);
                              callback(certData);
                        } catch (error) {
                              console.error("Error loading certificate from file:", error);
                              callback(null);
                        }
                  } else {
                        callback(null);
                  }
            }
      });

      socket.on("SendMessage",(data)=>{
            db.map(user=>{
                  if(user.online){
                        if(data.who === "Lobby"){
                              io.sockets.to(user.socketId).emit("IncomingMessage",{
                                    mesaj: data.mesaj,
                                    name: data.name,
                                    isLobby: true,
                                    signature: data.signature
                              })
                        }
                        else if(data.who.toLowerCase() === user.name.toLowerCase()){
                              io.sockets.to(user.socketId).emit("IncomingMessage",{
                                    mesaj: data.mesaj,
                                    name: data.name,
                                    isLobby: false,
                                    signature: data.signature
                              })
                        }
                        else if(data.name === user.name){
                              io.sockets.to(user.socketId).emit("IncomingMessage",{
                                    mesaj: data.mesaj,
                                    name: data.name,
                                    who: data.who,
                                    isLobby: false,
                                    signature: data.signature
                              })
                        }
                  }
                  else{
                        if(data.who === user.name){
                              Mesajlar.push({
                                    mesaj: data.mesaj,
                                    kime: user.name,
                                    kimden: data.name,
                                    lobbymi: false,
                                    signature: data.signature
                              })
                        }
                        else if(data.who === "Lobby"){
                              Mesajlar.push({
                                    mesaj: data.mesaj,
                                    kime: user.name,
                                    kimden: data.name,
                                    lobbymi: true,
                                    signature: data.signature
                              })
                        }
                  }
            })
      })

      socket.on("disconnect",()=>{
            const id = socket.id
            const user = db.find((user) => user.socketId === id);
            if(user){
                  user.online = false
                  var users = []
                  db.map((item)=>users.push({name:item.name,online:item.online,id:item.id}))
                  socket.broadcast.emit("online",users)
            }
      })
})

app.use(Chat)

server.listen(PORT,()=>{
      console.log("Server has started on port",PORT);
}) 