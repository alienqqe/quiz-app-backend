const bcrypt = require('bcrypt')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const supabase = require('../supabaseClient')
const dotenv = require('dotenv')

dotenv.config()

const REFRESH_SECRET = process.env.REFRESH_SECRET

exports.getHistory = async (req, res) => {
  const token = req.cookies.refreshToken
  if (!token) return res.status(401).json({ error: 'No refresh token' })

  try {
    const decoded = jwt.verify(token, REFRESH_SECRET)

    const { data, error } = await supabase
      .from('users')
      .select('quizes')
      .eq('username', decoded.username)
      .single()

    if (error) {
      return res.status(400).json({ message: error.message })
    }

    return res.status(200).json(data.quizes || [])
  } catch (err) {
    console.error(err)
    return res.status(401).json({ message: 'Invalid or expired token' })
  }
}

exports.pushQuiz = async (req, res) => {
  const token = req.cookies.refreshToken
  if (!token) return res.status(401).json({ error: 'No refresh token' })

  try {
    const decoded = jwt.verify(token, REFRESH_SECRET)
    const { quiz } = req.body
    if (!quiz) {
      return res.status(400).json({ error: 'Quiz data missing in body' })
    }
    const { data: historyData, error: historyError } = await supabase
      .from('users')
      .select('quizes')
      .eq('username', decoded.username)
      .single()

    if (historyError) {
      return res.status(400).json({ message: historyError.message })
    }
    const oldHistory = historyData.quizes || []
    const newHistory = [...oldHistory, quiz]

    const { error: updateError } = await supabase
      .from('users')
      .update({ quizes: newHistory })
      .eq('username', decoded.username)

    if (updateError) {
      return res.status(400).json({ message: updateError.message })
    }

    return res.status(200).json({ success: true, quizes: newHistory })
  } catch (err) {
    console.error(err)
    return res.status(500).json({ message: 'Internal server error' })
  }
}

exports.deleteQuiz = async (req, res) => {
  const token = req.cookies.refreshToken
  if (!token) return res.status(401).json({ error: 'No refresh token' })

  try {
    const decoded = jwt.verify(token, REFRESH_SECRET)
    const id = req.params

    if (!id) {
      return res.status(400).json({ message: 'Quiz id is required' })
    }

    const { data: historyData, error: historyError } = await supabase
      .from('users')
      .select('quizes')
      .eq('username', decoded.username)
      .single()

    if (historyError) {
      return res.status(400).json({ message: historyError.message })
    }

    const oldHistory = historyData.quizes || []

    const newHistory = oldHistory.filter((quiz) => quiz.id !== id)

    const { error: updateError } = await supabase
      .from('users')
      .update({ quizes: newHistory })
      .eq('username', decoded.username)

    if (updateError) {
      return res.status(400).json({ message: updateError.message })
    }

    return res.status(200).json({ quizes: newHistory })
  } catch (err) {
    console.error(err)
    return res.status(401).json({ message: 'Invalid or expired token' })
  }
}
