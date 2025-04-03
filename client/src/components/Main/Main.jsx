import React,{useState,useEffect} from "react"
import {Form,Button} from "react-bootstrap"
import {AiOutlineSend} from "react-icons/ai"
import Cookies from "js-cookie"
import {Redirect} from "react-router-dom"
import { encryptMessage, decryptMessage, signMessage, verifySignature } from '../../utils/rsaUtils';

//Panel Components
import User from "./Components/Panel/User"
import Lobby from "./Components/Panel/Lobby"
import UsersUser from "./Components/Panel/UsersUser"


//Chat Components
import LobbyDes from "./Components/Chat/LobbyDes"
import UserDes from "./Components/Chat/UserDes"
import OwnMsg from "./Components/Chat/Msg"
import SenderMsg from "./Components/Chat/MsgLobby"

//Socket
import {socket} from "../../socket"
var user = {id:"",name:""}


function Main() {
  const [isAuth,setAuth] = useState(false)
  const [People,SetPeople] = useState([])
  const [allMsg,SetAllMsg] = useState("")
  
  const [selectedUser,setSelectedUser] = useState("Lobby")
  const [onlineStatus,setOnlineStatus] = useState("Offline")

  //Message
  const [mesaj,setMesaj] = useState("")

  useEffect(()=>{
    let token = Cookies.get("token")

    socket.emit("auth",token)
    
  },[])

  useEffect(() => {
    const handleIncomingMessage = async (data) => {
        try {
            console.log("Incoming message data:", {
                name: data.name,
                mesaj: data.mesaj,
                signature: data.signature,
                isLobby: data.isLobby,
                who: data.who
            });
            
            // Skip processing if this is our own message
            if (data.name === user.name) {
                return;
            }
            
            // Get sender's certificate from server
            socket.emit("getUserCertificate", { username: data.name }, async (senderCertificate) => {
                if (!senderCertificate) {
                    console.error("Failed to get sender's certificate");
                    return;
                }

                try {
                    // Get encryption private key from cookies
                    const encryptionPrivateKey = Cookies.get("encryptionPrivateKey");
                    if (!encryptionPrivateKey) {
                        console.error("Encryption private key not found in cookies");
                        return;
                    }
                    
                    // Decrypt the message
                    console.log("Message to decrypt:", data.mesaj);
                    const decryptedMessage = await decryptMessage(data.mesaj, encryptionPrivateKey);
                    
                    
                    // Verify signature using sender's public key from certificate
                    const isValid = await verifySignature(
                        decryptedMessage,
                        data.signature,
                        senderCertificate.publicKeys.signingPublicKey
                    );
                    
                    if (!isValid) {
                        console.error("Message signature verification failed");
                        return;
                    }
                    
                    console.log("Message signature verified successfully");
                    
                    // Store message in local storage
                    if (data.isLobby) {
                        let temp = await localStorage.getItem((user.name + "Lobby"));
                        if (temp) {
                            localStorage.setItem((user.name + "Lobby"), (temp + `${data.name}:${decryptedMessage}-|-`));
                        } else {
                            localStorage.setItem((user.name + "Lobby"), `${data.name}:${decryptedMessage}-|-`);
                        }
                    } else {
                        let temp = await localStorage.getItem((user.name + data.name));
                        if (temp) {
                            localStorage.setItem((user.name + data.name), (temp + `${data.name}:${decryptedMessage}-|-`));
                        } else {
                            localStorage.setItem((user.name + data.name), `${data.name}:${decryptedMessage}-|-`);
                        }
                    }
                    
                    // Update the display
                    let allMessage = await localStorage.getItem((user.name + selectedUser));
                    SetAllMsg(allMessage);
                } catch (error) {
                    console.error("Error processing message:", error);
                }
            });
        } catch (error) {
            console.error("Error in handleIncomingMessage:", error);
        }
    };

    socket.on("IncomingMessage", handleIncomingMessage);
    return () => {
        socket.off("IncomingMessage", handleIncomingMessage);
    };
  }, [selectedUser]);

  // Separate useEffect for online status updates
  useEffect(() => {
    const handleOnlineStatus = (info) => {
        var tempPeople = info.filter((item) => item.id !== user.id);
        SetPeople(tempPeople);
    };

    socket.on("online", handleOnlineStatus);

    return () => {
        socket.off("online", handleOnlineStatus);
    };
  }, []);

  // Separate useEffect for auth handling
  useEffect(() => {
    const handleAuth = (info) => {
        if (info.auth) {
            var tempPeople = info.users.filter((item) => item.id !== info.id);
            SetPeople(tempPeople);
            user = { id: String(info.id), name: String(info.name) };
        } else {
            setAuth(true);
        }
    };

    socket.on("auth", handleAuth);

    return () => {
        socket.off("auth", handleAuth);
    };
  }, []);

  useEffect(()=>{
    let allMessage = localStorage.getItem((user.name+selectedUser));
    SetAllMsg(allMessage)
  },[selectedUser])

  const handleSpace = e=>{
    const name = e.target.getAttribute('name')
    setSelectedUser(name)

    var secilen = People.find(item=>item.name === name)

    if(secilen){
      if(secilen.online){
        setOnlineStatus("Online")
      }
      else{
        setOnlineStatus("Offline")
      }
    }
  }

  const handleMesaj = e =>{
    setMesaj(e.target.value)
  }

  const SendMessage = async (e) => {
    e.preventDefault();
    if (!mesaj.trim() || !selectedUser) return;

    try {
        console.log("Sending message to:", selectedUser);
        console.log("Message:", mesaj);

        // Store sender's message in local storage
        let temp = await localStorage.getItem((user.name + selectedUser));
        if (temp) {
            localStorage.setItem((user.name + selectedUser), (temp + `${user.name}:${mesaj}-|-`));
        } else {
            localStorage.setItem((user.name + selectedUser), `${user.name}:${mesaj}-|-`);
        }

        // Update display immediately
        let allMessage = await localStorage.getItem((user.name + selectedUser));
        SetAllMsg(allMessage);

        // Get sender's certificate from cookies
        const senderCertificate = JSON.parse(Cookies.get("certificate"));
        const senderSigningPrivateKey = Cookies.get("signingPrivateKey");

        console.log("Sender's signing private key:", senderSigningPrivateKey);

        // Get recipient's certificate from server
        socket.emit("getUserCertificate", { username: selectedUser }, async (recipientCertificate) => {
            console.log("Recipient's certificate:", recipientCertificate);
            if (!recipientCertificate) {
                console.error("Failed to get recipient's certificate");
                return;
            }

            try {
                // Generate signature for the message
                const signature = await signMessage(mesaj, senderSigningPrivateKey);
                console.log("Generated signature:", signature);

                // Encrypt message with recipient's public key
                const encryptedMessage = await encryptMessage(mesaj, recipientCertificate.publicKeys.encryptionPublicKey);
                console.log("Encrypted message:", encryptedMessage);

                // Create message data object without sender's public key
                const messageData = {
                    mesaj: encryptedMessage,
                    signature: signature,
                    name: user.name,
                    who: selectedUser,
                    isLobby: selectedUser === "Lobby"
                };
                console.log("Sending message data:", messageData);

                // Send message
                socket.emit("SendMessage", messageData);
            } catch (error) {
                console.error("Error preparing message:", error);
            }
        });
    } catch (error) {
        console.error("Error sending message:", error);
    }
    setMesaj("");
  };

  // Load messages when user or selected user changes
  useEffect(() => {
    const loadMessages = async () => {
      try {
        let allMessage = await localStorage.getItem((user.name + selectedUser));
        SetAllMsg(allMessage);
      } catch (error) {
        console.error("Error loading messages:", error);
      }
    };

    loadMessages();
  }, [user.name, selectedUser]);

  return (
      <div id="Page">
        {isAuth && <Redirect to="/" />}
        <div style={{height:"2vh"}}></div>
        <div id="Main">
          <div id="Panel">
            <User/>
            <div id="Users">
              <Lobby onClick={handleSpace}/>
              {/* Map */}
              {People.map(item=>(<UsersUser key={item.name} name={item.name} online={item.online} onClick={handleSpace}/>))}
              {/* Map */}
            </div>
          </div>
          <div id="Chat">
            {selectedUser === "Lobby" ? <LobbyDes/> : <UserDes name={selectedUser} online={onlineStatus}/>}
            <div className="Mesaj">
              <div id="scroll-style" className="chat-space">
                {
                  allMsg && allMsg.split("-|-").filter(item=>item !=="").map((item,index)=>{
                    var a = item.split(":")
                    // console.log("a value",a)
                    if(a[0] === user.name){
                      return(<OwnMsg key={index}>{a[1]}</OwnMsg>)
                    }
                    else{
                      // console.log("a[0]",a[0])
                      return(<SenderMsg key={index} name={a[0]}>{a[1]}</SenderMsg>)
                    }
                  })
                }
              </div>
              <div className="send-msg-space">
                <div className="send-msg-text-space">
                <Form.Control size="lg" type="text" onChange={handleMesaj} value={mesaj} placeholder="Type a message" className="send-msg-text"/>
                </div>
                <div className="send-msg-button-space">
                  <Button className="send-msg-button" onClick={SendMessage}><AiOutlineSend/></Button>
                </div>
              </div>
            </div>
          </div>
        </div> 
      </div>
     
  );
}

export default Main;
