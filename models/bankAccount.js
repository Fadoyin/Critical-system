const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bankAccountSchema = new Schema({
    Passport_id:{
        type: String,
        required: true
    },
    account_number:{
        type: String,
        required: true
    },
    account_name:{
        type: String,
        required: true
    },
    user:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    balance: {
        type: mongoose.Schema.Types.Decimal128,
        required: true,
        default: mongoose.Types.Decimal128.fromString('0.0')
    }
}, {timestamps:true})   
 module.exports = mongoose.model('BankAccount',bankAccountSchema);