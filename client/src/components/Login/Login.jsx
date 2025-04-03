import React, { useEffect, useState } from 'react';
import {Container,Row,Col,CardGroup,Card, InputGroup,FormControl,Button,Form,Alert} from "react-bootstrap"
import {HiOutlineUser} from "react-icons/hi"
import {GoLock} from "react-icons/go"
import {socket} from "../../socket"
import {Redirect} from "react-router-dom"
import Cookies from 'js-cookie'
import { generateKeyPair, generateCertificate } from '../../utils/rsaUtils';
import "./login.css"


export default function Login() {

      const [userInfo,SetUserInfo] = useState({name:"",pass:""})
      const [isAuth,setAuth] = useState(false)
      const [Check,setCheck] = useState(false)


      useEffect(()=>{
            socket.on("login",async data=>{
                  if(data.auth){
                        try {
                              console.log("Login Starts")
                              // Generate RSA key pairs and certificate
                              const { 
                                    encryptionPublicKey, 
                                    encryptionPrivateKey,
                                    signingPublicKey,
                                    signingPrivateKey 
                              } = await generateKeyPair();
                              console.log("Key pairs generated successfully");
                              console.log("Encryption Public Key:", encryptionPublicKey);
                              console.log("Encryption Private Key:", encryptionPrivateKey);
                              console.log("Signing Public Key:", signingPublicKey);
                              console.log("Signing Private Key:", signingPrivateKey);
                              
                              // Ensure username is available
                              if (!data.name) {
                                    throw new Error("Username is not set in server response");
                              }
                              
                              
                              const certificate = generateCertificate({
                                    encryptionPublicKey,
                                    signingPublicKey
                              }, data.name);
                              console.log("Certificate generated successfully");
                              
                              if (!certificate) {
                                    throw new Error("Certificate is null or undefined");
                              }
                              if (!certificate.subject) {
                                    throw new Error("Certificate subject is missing");
                              }
                              if (!certificate.publicKeys) {
                                    throw new Error("Certificate public keys are missing");
                              }
                              if (!certificate.issuedAt) {
                                    throw new Error("Certificate issuedAt is missing");
                              }
                              if (!certificate.expiresAt) {
                                    throw new Error("Certificate expiresAt is missing");
                              }
                              
                              // Store keys and certificate in cookies
                              console.log("Storing private data keys in cookies...");
                              Cookies.set("token", data.token, { expires: 1 });
                              Cookies.set("encryptionPrivateKey", encryptionPrivateKey, { expires: 1 });
                              Cookies.set("signingPrivateKey", signingPrivateKey, { expires: 1 });
                              Cookies.set("certificate", JSON.stringify(certificate), { expires: 1 });
                              console.log("Keys stored in cookies");
                              
                              // Format certificate data for server
                              const certData = {
                                    username: data.name,
                                    certificate: {
                                          subject: certificate.subject,
                                          publicKeys: certificate.publicKeys,
                                          issuedAt: certificate.issuedAt,
                                          expiresAt: certificate.expiresAt
                                    }
                              };
                              
                              if (!certData.username) {
                                    throw new Error("Username is missing in formatted data");
                              }
                              if (!certData.certificate) {
                                    throw new Error("Certificate object is missing in formatted data");
                              }
                              if (!certData.certificate.subject) {
                                    throw new Error("Subject is missing in formatted certificate");
                              }
                              if (!certData.certificate.publicKeys) {
                                    throw new Error("Public keys are missing in formatted certificate");
                              }
                              if (!certData.certificate.issuedAt) {
                                    throw new Error("IssuedAt is missing in formatted certificate");
                              }
                              if (!certData.certificate.expiresAt) {
                                    throw new Error("ExpiresAt is missing in formatted certificate");
                              }
                              
                              console.log("Sending certificate data to server");
                              
                              // Send certificate to server with timeout
                              const timeout = setTimeout(() => {
                                    console.error("Certificate storage request timed out");
                                    setCheck(true);
                                    setTimeout(()=>{setCheck(false)},10000);
                              }, 5000);
                              
                              socket.emit("storeCertificate", certData, (success) => {
                                    clearTimeout(timeout);
                                    if (success) {
                                          console.log("Certificate stored successfully on server");
                                          SetUserInfo({name:"",pass:""});
                                          setTimeout(()=>{setAuth(true)},500);
                                    } else {
                                          console.error("Failed to store certificate on server");
                                          setCheck(true);
                                          setTimeout(()=>{setCheck(false)},10000);
                                    }
                              });
                        } catch (error) {
                              console.error("Error in login process:", error);
                              console.error("Error stack:", error.stack);
                              setCheck(true);
                              setTimeout(()=>{setCheck(false)},10000);
                        }
                  }
                  else{
                        setCheck(true)
                        setTimeout(()=>{setCheck(false)},10000)
                  }
            })
      },[])

      useEffect(()=>{
            let token = Cookies.get("token")
        
            socket.emit("auth",token)
            
          },[])
        
      useEffect(()=>{
            socket.on("auth",(info)=>{
                  if(info.auth){
                        setAuth(true)
                  }
            })
      },[])

      const Submit = (e)=>{
            e.preventDefault()
            const currentUserInfo = { ...userInfo }; // Create a copy of the current user info
            socket.emit("login", currentUserInfo)
            // Don't clear the form until after successful login
      }

      const HandleChange = (e)=>{
            
            SetUserInfo(preventValue=>{
                  if(e.target.name==="UserName")
                        return{...preventValue,name:e.target.value}
                  else if(e.target.name==="Password")
                        return{...preventValue,pass:e.target.value}
            })
      }

      return (
      <div className="login" id="full-height">
            {isAuth && <Redirect to="/main" />}
            {/* {Check && <div className="login-alert"><Fade top><Alert variant="danger">Kullanıcı Adı veya Şifre Hatalı!</Alert></Fade></div>} */}
            <Container>
            <Row className="justify-content-center">
            <Col md="1" className="p-2 cikolata-kenar"></Col>
            <Col md="10" className="p-0">
                  <CardGroup>
                  <Card className="p-4 login-left">
                  <Card.Body>
                        <Form onSubmit={Submit}>
                              <h1 className="text-white" >Login</h1>
                              <p className="text-muted">Sign In to your account</p>
                              
                              <InputGroup className="mb-3">
                              <InputGroup.Prepend>
                              <InputGroup.Text className="login-input"><div><HiOutlineUser/></div></InputGroup.Text>
                              </InputGroup.Prepend>
                              
                              <FormControl
                              placeholder="Username"
                              type="text"
                              className="login-input"
                              onChange={HandleChange}
                              value={userInfo.name}
                              name="UserName"
                              />
                              </InputGroup>
                              <InputGroup className="mb-4">
                              <InputGroup.Prepend>
                              <InputGroup.Text className="login-input"><div><GoLock/></div></InputGroup.Text>
                              </InputGroup.Prepend>
                              <FormControl
                              placeholder="Password"
                              type="password"
                              className="login-input"
                              onChange={HandleChange}
                              value={userInfo.pass}
                              name="Password"
                              />
                              </InputGroup>
                              <Row>
                              <Col>
                              <Button className="px-4" type="submit">Login</Button>
                              </Col>
                              {/* <Col className="text-right">
                              <button className="btn btn-link px-0" type="button">Forgot password?</button>
                              </Col> */}
                              </Row>
                        </Form>
                  </Card.Body>
                  </Card>
                  {/* <Card className="text-white py-5 login-right" id="log-reg" style={{width:"44%"}}>
                  <Card.Body className="text-center">
                        <div>
                        <h2>Sign up</h2>
                        <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
                        <Button variant="outline-light" size="lg"className="mt-3">Register</Button>
                        </div>
                  </Card.Body>
                  </Card> */}
                  </CardGroup>
            </Col>
            </Row>
            </Container>
      </div>
      )
}