const express = require("express");
require("./connection/Dbconnection")
 const app = express();


 app.use(express.json())


 app.listen(5000,()=>{
    console.log("server is running at 5000")
 })