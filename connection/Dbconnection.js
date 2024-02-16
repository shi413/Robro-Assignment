const { default: mongoose } = require("mongoose");

mongoose.connect('mongodb://127.0.0.1:27017/Robro')
.then(()=>console.log('connected!')).catch(()=>{console.log("Not Connected")});
