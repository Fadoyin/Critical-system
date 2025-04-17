const mongoose = require('mongoose');
const BankAccount = require('../models/bankAccount.js');
const generateAccountNumber=(length = 10)=> {
    let accountNumber = '';
    for (let i = 0; i < length; i++) {
        accountNumber += Math.floor(Math.random() * 10); // Random digit (0-9)
    }
    return accountNumber;
}
const createAccountDetails = async(req,res)=>{
    const user = req.user._id;
if (!user) {
    return res.status(400).json({error: 'User id not found'});
}
const accountExist = await BankAccount.findOne({user});
if (accountExist)
{
   res.status(400).json({error:"Account already exist"});
}
    else{
        try{
        const account_number = generateAccountNumber()
        console.log(account_number);
       const { account_name, Passport_id, balance } = req.body;
       const account = await BankAccount.create({account_name, account_number, Passport_id, balance, user});
       res.status(200).json(account);
        }
        catch(error)
        {
            res.status(400).json({error: error.message});
        }
    }
}
const getAccountDetails = async(req,res)=>{
    const user = req.user._id;
   try{
        const account = await BankAccount.find({user});
       res.status(200).json (account);
   }
   catch(error)
   {
    return res.status(400).json({error: error.message});
   }
}
const getUserAccounts = async(req,res)=>{

    try{
        const accounts = await BankAccount.find();
      res.status(200).json(accounts);
    }
    catch(error)
    {
        res.status(400).json({error: error.message});
    }
}
const updateAccount = async(req,res)=>{
    const {id} = req.params;
    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(404).json({error: 'Invalid account id'});
    }
   try {
    const account = await BankAccount.findOneAndUpdate({_id: id}, {...req.body});
    res.status(200).json(account);
   }
   catch (error){
    return res.status(400).json({error: error.message});
   }
   }
   const deleteAccount = async(req,res)=>{
    const {id} = req.params;
    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(404).json({error: 'Invalid account id'});
    }
    try {
        const account = await BankAccount.findOneAndDelete({_id: id});
        res.status(200).json(account);
       }
       catch (error){
        return res.status(400).json({error: error.message});
       }
}
module.exports = {
    getAccountDetails, createAccountDetails, getUserAccounts, updateAccount, deleteAccount
}