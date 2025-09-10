const express = require('express')
const {
  getHistory,
  pushQuiz,
  deleteQuiz,
} = require('../controllers/historyController')
const authenticateToken = require('../middleware')

const router = express.Router()
router.get('/getHistory', authenticateToken, getHistory)
router.post('/pushQuiz', authenticateToken, pushQuiz)

router.delete('/:id', authenticateToken, deleteQuiz)

module.exports = router
