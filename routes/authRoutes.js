const express = require('express')
const {
  register,
  login,
  refresh,
  me,
} = require('../controllers/authController')
const authenticateToken = require('../middleware')

const router = express.Router()
router.post('/register', register)
router.post('/login', login)
router.post('/refresh', refresh)
router.get('/me', authenticateToken, me)

module.exports = router
