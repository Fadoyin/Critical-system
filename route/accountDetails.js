const express = require('express');
const router = express.Router();
const { getAccountDetails, createAccountDetails, getUserAccounts, updateAccount, deleteAccount} = require('../controllers/accountDetails');
const auth = require('../Middleware/auth');
router.post('/', auth,createAccountDetails);
router.get ('/',auth,getAccountDetails);
router.get ('/UserAccounts',getUserAccounts);
router.put ('/:id',updateAccount)
router.delete ('/:id',deleteAccount);
module.exports = router;