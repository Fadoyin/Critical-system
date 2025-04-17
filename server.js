const express = require('express');
const mongoose = require('mongoose');
const users = require('./route/users');
const accountDetails = require('./route/accountDetails');
require('dotenv').config();
const app = express();
app.use(express.json());
app.use ((req,res, next)=> {
    console.log(req.path, req.body);
    next();
})
    
/*app.use('/',(req,res)=>{
    res.json({message: "Welcome to backend"});
}) */
const PORT = process.env.PORT || 5000;
app.use('/api/users', users)
app.use('/api/accounts', accountDetails);
mongoose.connect(process.env.MONGO_URI).then(()=>{
    app.listen(PORT,()=>{
        console.log('Mongoose connected on port',PORT);
    })
}).catch((error)=>{
    console.log(error);
})